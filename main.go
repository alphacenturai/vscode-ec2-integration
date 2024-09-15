package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmTypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

const (
	maxIteration   = 5
	sleepDuration  = 5 * time.Second
	defaultTimeout = 60
)

type Config struct {
	InstanceName     string
	Port             string
	AwsProfile       string
	AwsRegion        string
	InstanceType     string
	VpcName          string
	SshPublicKeyPath string
	ManagedPolicyArn string // Optional, can be an empty string if not provided
}

func main() {

	var showHelp bool
	var (
		instanceName     string
		port             string
		awsProfile       string
		awsRegion        string
		instanceType     string
		vpcName          string
		sshPublicKeyPath string
		managedPolicyArn string
	)

	// Command-line flags
	flag.BoolVar(&showHelp, "h", false, "Show help message")
	flag.StringVar(&instanceName, "instance-name", "", "Instance name")
	flag.StringVar(&port, "port", "", "Port number")
	flag.StringVar(&awsProfile, "aws-profile", "", "AWS profile name")
	flag.StringVar(&awsRegion, "aws-region", "", "AWS region")
	flag.StringVar(&instanceType, "instance-type", "", "Instance type")
	flag.StringVar(&vpcName, "vpc-name", "", "VPC name")
	flag.StringVar(&sshPublicKeyPath, "ssh-public-key-path", "", "Path to SSH public key")
	flag.StringVar(&managedPolicyArn, "managed-policy-arn", "", "Managed policy ARN")
	flag.Parse()

	// If -h flag is provided, print usage and exit
	if showHelp {
		printUsage()
		return
	}

	// Check if positional arguments are provided and validate length
	if len(os.Args) < 8 || (len(os.Args) == 9 && managedPolicyArn == "") {
		log.Fatal("Insufficient arguments provided or missing managed policy ARN")
	}

	// Use either positional or named arguments
	instanceName = getArgumentOrFlagValue(instanceName, os.Args[1], "instance-name")
	port = getArgumentOrFlagValue(port, os.Args[2], "port")
	awsProfile = getArgumentOrFlagValue(awsProfile, os.Args[3], "aws-profile")
	awsRegion = getArgumentOrFlagValue(awsRegion, os.Args[4], "aws-region")
	instanceType = getArgumentOrFlagValue(instanceType, os.Args[5], "instance-type")
	vpcName = getArgumentOrFlagValue(vpcName, os.Args[6], "vpc-name")
	sshPublicKeyPath = getArgumentOrFlagValue(sshPublicKeyPath, os.Args[7], "ssh-public-key-path")

	// If managedPolicyArn is not provided via flag, use positional argument
	if managedPolicyArn == "" && len(os.Args) >= 9 {
		managedPolicyArn = os.Args[8]
	}

	appConfig := Config{
		InstanceName:     instanceName,
		Port:             port,
		AwsProfile:       awsProfile,
		AwsRegion:        awsRegion,
		InstanceType:     instanceType,
		VpcName:          vpcName,
		SshPublicKeyPath: sshPublicKeyPath,
		ManagedPolicyArn: managedPolicyArn,
	}

	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(appConfig.AwsRegion),
		config.WithSharedConfigProfile(appConfig.AwsProfile),
	)
	if err != nil {
		log.Fatalf("Failed to load appConfiguration: %v", err)
	}

	ec2Client := ec2.NewFromConfig(cfg)
	iamClient := iam.NewFromConfig(cfg)
	ssmClient := ssm.NewFromConfig(cfg)

	createOrUpdateInstanceRole(ctx, iamClient, appConfig)

	amiID := getLatestAmiID(ctx, ec2Client, appConfig.InstanceType)
	vpcID := getVpcID(ctx, ec2Client, appConfig.VpcName)
	subnetID := getSubnetID(ctx, ec2Client, vpcID)

	fmt.Printf("Using VPC ID: %s\n", vpcID)
	fmt.Printf("Using Subnet ID: %s\n", subnetID)

	fmt.Println("Updating for Access..")
	laptopIP := getLaptopIP()

	fmt.Println("Checking Security Group")
	sgID := createOrUpdateSecurityGroup(ctx, ec2Client, appConfig.InstanceName, vpcID, laptopIP)
	fmt.Printf("Using Security Group ID: %s\n", sgID)

	fmt.Println("Found the Public Key")
	sshPublicKey, err := os.ReadFile(appConfig.SshPublicKeyPath)
	if err != nil {
		log.Fatalf("Failed to read SSH public key: %v", err)
	}

	pubKey := strings.ReplaceAll(string(sshPublicKey), "\n", "")

	userData := createUserData(string(pubKey))

	instanceID := findOrCreateInstance(ctx, ec2Client, appConfig, amiID, subnetID, sgID, userData)

	waitForInstanceOnline(ctx, ssmClient, instanceID)

	fmt.Println("Starting SSM session...")
	startSSMSession(ctx, ssmClient, instanceID, appConfig.Port)
}

// getArgumentOrFlagValue returns the value from flag or args based on priority
func getArgumentOrFlagValue(flagValue, argValue, flagName string) string {
	if flagValue != "" {
		return flagValue
	}
	if argValue != "" {
		log.Printf("Using positional argument for %s: %s\n", flagName, argValue)
		return argValue
	}
	log.Fatalf("Missing required argument or flag: %s\n", flagName)
	return ""
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Printf("  %s [flags] <instance-name> <port> <aws-profile> <aws-region> <instance-type> <vpc-name> <ssh-public-key-path> <managed-policy-arn>\n", os.Args[0])
	fmt.Println("\nFlags:")
	flag.PrintDefaults()
}

func createOrUpdateInstanceRole(ctx context.Context, iamClient *iam.Client, appConfig Config) {
	roleName := fmt.Sprintf("%s-Role", appConfig.InstanceName)
	_, err := iamClient.GetRole(ctx, &iam.GetRoleInput{RoleName: &roleName})
	if err != nil {
		// Role doesn't exist, create it
		fmt.Printf("Creating IAM role: %s\n", roleName)
		assumeRolePolicyDocument := `{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": {"Service": "ec2.amazonaws.com"},
				"Action": "sts:AssumeRole"
			}]
		}`
		_, err = iamClient.CreateRole(ctx, &iam.CreateRoleInput{
			RoleName:                 &roleName,
			AssumeRolePolicyDocument: &assumeRolePolicyDocument,
		})
		if err != nil {
			log.Fatalf("Failed to create IAM role: %v", err)
		}

		// Attach policy to role if ManagedPolicyArn is provided
		if appConfig.ManagedPolicyArn != "" {
			fmt.Printf("Attaching managed policy (%s) to IAM role %s\n", appConfig.ManagedPolicyArn, roleName)
			_, err = iamClient.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
				RoleName:  &roleName,
				PolicyArn: &appConfig.ManagedPolicyArn,
			})
			if err != nil {
				log.Fatalf("Failed to attach policy to IAM role: %v", err)
			}
		}

		// Create instance profile
		_, err = iamClient.GetInstanceProfile(ctx, &iam.GetInstanceProfileInput{InstanceProfileName: &roleName})
		if err != nil {
			fmt.Printf("Creating IAM instance profile: %s\n", roleName)
			instanceProfile, err := iamClient.CreateInstanceProfile(ctx, &iam.CreateInstanceProfileInput{
				InstanceProfileName: &roleName,
			})
			if err != nil {
				log.Fatalf("Failed to create IAM instance profile: %v", err)
			}

			_, err = iamClient.AddRoleToInstanceProfile(context.TODO(), &iam.AddRoleToInstanceProfileInput{
				InstanceProfileName: instanceProfile.InstanceProfile.InstanceProfileName,
				RoleName:            aws.String(roleName),
			})
			if err != nil {
				log.Fatalf("Failed to attach IAM instance profile: %v", err)
			}
		} else {
			fmt.Printf("IAM instance profile %s already exists\n", roleName)
		}

		time.Sleep(20 * time.Second)
	} else {
		fmt.Printf("IAM role %s already exists\n", roleName)
	}
}

func getLatestAmiID(ctx context.Context, ec2Client *ec2.Client, instanceType string) string {
	ownerID := "099720109477" // Canonical's AWS account ID

	// Determine architecture based on instance type
	var architecture string
	if strings.HasPrefix(instanceType, "a1") || strings.HasPrefix(instanceType, "t4g") ||
		strings.HasPrefix(instanceType, "c6g") || strings.HasPrefix(instanceType, "m6g") ||
		strings.HasPrefix(instanceType, "r6g") || strings.HasPrefix(instanceType, "c7g") ||
		strings.HasPrefix(instanceType, "m7g") || strings.HasPrefix(instanceType, "r7g") {
		architecture = "arm64"
	} else {
		architecture = "amd64" // Covers both Intel and AMD
	}

	// Define name filters for Ubuntu 20.04 LTS
	nameFilter := fmt.Sprintf("ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-%s-server-*", architecture)

	resp, err := ec2Client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{ownerID},
		Filters: []types.Filter{
			{
				Name:   aws.String("name"),
				Values: []string{nameFilter},
			},
		},
	})
	if err != nil {
		log.Fatalf("Failed to get AMI ID: %v", err)
	}

	var latestImage *types.Image
	var latestDate = time.Time{}

	for i := range resp.Images {
		if resp.Images[i].CreationDate == nil {
			continue
		}
		creationDate, err := time.Parse(time.RFC3339, *resp.Images[i].CreationDate)
		if err != nil {
			log.Printf("Failed to parse creation date for image %s: %v", *resp.Images[i].ImageId, err)
			continue
		}
		if latestImage == nil || creationDate.After(latestDate) {
			latestImage = &resp.Images[i]
			latestDate = creationDate
		}
	}
	if latestImage == nil {
		log.Fatal("No AMI found")
	}

	return *latestImage.ImageId
}

func getVpcID(ctx context.Context, ec2Client *ec2.Client, vpcName string) string {
	var vpcID string
	if vpcName == "" {
		fmt.Println("VPC name not provided. Using default VPC.")
		resp, err := ec2Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
			Filters: []types.Filter{
				{
					Name:   aws.String("isDefault"),
					Values: []string{"true"},
				},
			},
		})
		if err != nil || len(resp.Vpcs) == 0 {
			log.Fatalf("Failed to get default VPC ID: %v", err)
		}
		vpcID = *resp.Vpcs[0].VpcId
	} else {
		resp, err := ec2Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
			Filters: []types.Filter{
				{
					Name:   aws.String("tag:Name"),
					Values: []string{vpcName},
				},
			},
		})
		if err != nil || len(resp.Vpcs) == 0 {
			log.Fatalf("Failed to get VPC ID: %v", err)
		}
		vpcID = *resp.Vpcs[0].VpcId
	}
	return vpcID
}

func getSubnetID(ctx context.Context, ec2Client *ec2.Client, vpcID string) string {
	resp, err := ec2Client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []string{vpcID},
			},
		},
	})
	if err != nil || len(resp.Subnets) == 0 {
		log.Fatalf("Failed to get subnet ID: %v", err)
	}
	return *resp.Subnets[0].SubnetId
}

func getLaptopIP() string {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		log.Fatalf("Failed to get laptop IP: %v", err)
	}
	defer resp.Body.Close()
	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read laptop IP: %v", err)
	}
	return string(ip)
}

func createOrUpdateSecurityGroup(ctx context.Context, ec2Client *ec2.Client, instanceName, vpcID, laptopIP string) string {
	sgName := fmt.Sprintf("%s-SG", instanceName)
	resp, err := ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []types.Filter{
			{Name: aws.String("group-name"), Values: []string{sgName}},
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
		},
	})
	if err != nil {
		log.Fatalf("Failed to describe security groups: %v", err)
	}

	var sgID string
	if len(resp.SecurityGroups) == 0 {
		createResp, err := ec2Client.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
			GroupName:   &sgName,
			Description: aws.String(fmt.Sprintf("Security group for %s", instanceName)),
			VpcId:       &vpcID,
		})
		if err != nil {
			log.Fatalf("Failed to create security group: %v", err)
		}
		sgID = *createResp.GroupId

		_, err = ec2Client.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId:    &sgID,
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(22),
			ToPort:     aws.Int32(22),
			CidrIp:     aws.String(fmt.Sprintf("%s/32", laptopIP)),
		})
		if err != nil {
			log.Fatalf("Failed to add inbound rule: %v", err)
		}
	} else {
		sgID = *resp.SecurityGroups[0].GroupId
	}

	return sgID
}

func createUserData(sshPublicKey string) string {
	userData := `#!/bin/bash
set -e

# Add SSH key to authorized_keys
mkdir -p /home/ubuntu/.ssh
echo %s >> /home/ubuntu/.ssh/authorized_keys
chmod 600 /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

# Update package lists and install awscli
apt-get update
apt-get install -y awscli

# Create directory for auto-shutdown script
mkdir -p /home/ubuntu/.auto-shutdown

# Create the VSCode test script
cat <<'EOT' > /home/ubuntu/.auto-shutdown/vscode_test.sh
#!/bin/bash
set -euo pipefail

SHUTDOWN_TIMEOUT=10
LOG_FILE="/home/ubuntu/.auto-shutdown/autoshutdown.log"

log() {
    echo "$(date '+%%Y-%%m-%%d %%H:%%M:%%S') - $1" >> "$LOG_FILE"
}

is_shutting_down() {
    systemctl is-active --quiet shutdown.target
}

is_vscode_connected() {
    pgrep -u ubuntu -f .vscode-server/bin/ -a | grep -v -F 'shellIntegration-bash.sh'
}

log "Script started"

if is_shutting_down; then
    log "System is shutting down"
    if [[ ! $SHUTDOWN_TIMEOUT =~ ^[0-9]+$ ]] || is_vscode_connected; then
        log "Cancelling shutdown due to active VS Code connection or invalid timeout"
        sudo shutdown -c
        log "Shutdown cancelled"
        echo > "/home/ubuntu/.auto-shutdown/autoshutdown-timestamp"
        log "Updated autoshutdown timestamp"
    else
        log "Updating autoshutdown timestamp without cancelling shutdown"
        date +%%s > "/home/ubuntu/.auto-shutdown/autoshutdown-timestamp"
    fi
else
    log "System is not shutting down"
    if [[ $SHUTDOWN_TIMEOUT =~ ^[0-9]+$ ]] && ! is_vscode_connected; then
        log "No active VS Code connections detected, scheduling shutdown in $SHUTDOWN_TIMEOUT minutes"
        sudo shutdown -h +$SHUTDOWN_TIMEOUT
        log "Shutdown scheduled"
    else
        log "Shutdown not scheduled due to invalid timeout or active VS Code connection"
    fi
fi

log "Script finished"

EOT

# Set correct permissions and add to crontab
chmod +x /home/ubuntu/.auto-shutdown/vscode_test.sh
chown ubuntu:ubuntu /home/ubuntu/.auto-shutdown/vscode_test.sh
(crontab -u ubuntu -l 2>/dev/null; echo "*/5 * * * * /home/ubuntu/.auto-shutdown/vscode_test.sh") | crontab -u ubuntu -
`
	userData = fmt.Sprintf(userData, sshPublicKey)
	return base64.StdEncoding.EncodeToString([]byte(userData))
}

func findOrCreateInstance(ctx context.Context, ec2Client *ec2.Client, appConfig Config, amiID, subnetID, sgID, userData string) string {
	resp, err := ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("tag:Name"),
				Values: []string{appConfig.InstanceName},
			},
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running", "stopped"},
			},
		},
	})
	if err != nil {
		log.Fatalf("Failed to search for instance: %v", err)
	}

	var instanceID string
	if len(resp.Reservations) == 0 || len(resp.Reservations[0].Instances) == 0 {
		fmt.Println("Instance not found. Creating a new instance.")
		createResp, err := ec2Client.RunInstances(ctx, &ec2.RunInstancesInput{
			ImageId:      aws.String(amiID),
			InstanceType: types.InstanceType(appConfig.InstanceType),
			MinCount:     aws.Int32(1),
			MaxCount:     aws.Int32(1),
			SubnetId:     aws.String(subnetID),
			UserData:     aws.String(userData),
			IamInstanceProfile: &types.IamInstanceProfileSpecification{
				Name: aws.String(fmt.Sprintf("%s-Role", appConfig.InstanceName)),
			},
			BlockDeviceMappings: []types.BlockDeviceMapping{
				{
					DeviceName: aws.String("/dev/sda1"),
					Ebs: &types.EbsBlockDevice{
						VolumeSize: aws.Int32(100),
						VolumeType: types.VolumeTypeGp2,
					},
				},
			},
			TagSpecifications: []types.TagSpecification{
				{
					ResourceType: types.ResourceTypeInstance,
					Tags: []types.Tag{
						{
							Key:   aws.String("Name"),
							Value: aws.String(appConfig.InstanceName),
						},
					},
				},
			},
			SecurityGroupIds: []string{sgID},
		})
		if err != nil {
			log.Fatalf("Failed to create new instance: %v", err)
		}
		instanceID = *createResp.Instances[0].InstanceId
		fmt.Printf("Created instance with ID: %s\n", instanceID)
	} else {
		instanceID = *resp.Reservations[0].Instances[0].InstanceId
		instanceState := *resp.Reservations[0].Instances[0].State.Name

		if instanceState == types.InstanceStateNameStopped {
			fmt.Printf("Instance %s is stopped. Starting it...\n", instanceID)
			_, err = ec2Client.StartInstances(ctx, &ec2.StartInstancesInput{
				InstanceIds: []string{instanceID},
			})
			if err != nil {
				log.Fatalf("Failed to start the instance: %v", err)
			}
			fmt.Println("Waiting for the instance to start...")
			showProgress(defaultTimeout) // Wait until the instance is fully started
		}
	}

	instanceStatus, err := ec2Client.DescribeInstanceStatus(ctx, &ec2.DescribeInstanceStatusInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		log.Fatalf("Failed to get instance status: %v", err)
	}

	if len(instanceStatus.InstanceStatuses) > 0 && instanceStatus.InstanceStatuses[0].InstanceState.Name != types.InstanceStateNameRunning {
		fmt.Printf("Starting instance %s...\n", instanceID)
		_, err = ec2Client.StartInstances(ctx, &ec2.StartInstancesInput{
			InstanceIds: []string{instanceID},
		})
		if err != nil {
			log.Fatalf("Failed to start the instance: %v", err)
		}
		fmt.Println("Waiting for the instance to come online...")
		showProgress(defaultTimeout)
	}

	return instanceID
}


func waitForInstanceOnline(ctx context.Context, ssmClient *ssm.Client, instanceID string) {
	for i := 0; i < maxIteration; i++ {
		resp, err := ssmClient.DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{
			Filters: []ssmTypes.InstanceInformationStringFilter{
				{
					Key:    aws.String("InstanceIds"),
					Values: []string{instanceID},
				},
			},
		})
		if err != nil {
			log.Fatalf("Failed to get instance status: %v", err)
		}

		if len(resp.InstanceInformationList) > 0 && resp.InstanceInformationList[0].PingStatus == ssmTypes.PingStatusOnline {
			fmt.Println("Instance is online.")
			return
		}

		if i == maxIteration-1 {
			log.Fatalf("Instance failed to come online after %d attempts", maxIteration)
		}

		time.Sleep(sleepDuration)
	}
}

func startSSMSession(ctx context.Context, ssmClient *ssm.Client, instanceID, port string) {
	input := &ssm.StartSessionInput{
		Target:       aws.String(instanceID),
		DocumentName: aws.String("AWS-StartSSHSession"),
		Parameters: map[string][]string{
			"portNumber": {port},
		},
	}

	const maxRetries = 3
	var attempt int

	for attempt = 0; attempt < maxRetries; attempt++ {
		resp, err := ssmClient.StartSession(ctx, input)
		if err != nil {
			// Check if the error indicates the instance is not connected
			if isTargetNotConnectedError(err) {
				log.Printf("Instance %s is not connected. Retrying...", instanceID)
				time.Sleep(time.Duration(attempt) * time.Second) // Wait before retrying
				continue
			}
			log.Fatalf("Failed to start SSM session: %v", err)
		}

		// Convert the response to JSON
		jsonResp, err := json.Marshal(resp)
		if err != nil {
			log.Fatalf("Failed to marshal SSM response: %v", err)
		}

		// Execute the session-manager-plugin
		cmd := exec.Command("session-manager-plugin", string(jsonResp), ssmClient.Options().Region, "StartSession")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err = cmd.Run()
		if err != nil {
			log.Fatalf("Failed to run session-manager-plugin: %v", err)
		}

		return // Successful session started
	}

	if attempt == maxRetries {
		log.Fatalf("Max retries exceeded. Failed to start SSM session for instance %s", instanceID)
	}
}

func isTargetNotConnectedError(err error) bool {
	// Check if the error is of type aws.Error and if the Code matches TargetNotConnected
	var targetNotConnectedError *ssmTypes.TargetNotConnected
	return errors.As(err, &targetNotConnectedError)
}

func showProgress(duration int) {
	for i := duration; i > 0; i-- {
		fmt.Printf("\rInitialization Progress: [%-50s] %02d:%02d:%02d",
			strings.Repeat("=", 50-i*50/duration)+strings.Repeat(" ", i*50/duration),
			i/3600, (i/60)%60, i%60)
		time.Sleep(time.Second)
	}
	fmt.Println()
}
