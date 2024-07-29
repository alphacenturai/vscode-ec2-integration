# Supercharge Your VS Code: Harness the Power of EC2 in the Cloud

![Build Status](https://github.com/alphacenturai/vscode-ec2-integration/actions/workflows/release.yml/badge.svg)
[![CodeQL](https://github.com/alphacenturai/vscode-ec2-integration/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/alphacenturai/vscode-ec2-integration/actions/workflows/github-code-scanning/codeql)

Hey there, code warriors! 👩‍💻👨‍💻 Tired of your local machine wheezing under the weight of your epic projects? Let's take your Visual Studio Code setup to the cloud with Amazon EC2 AMD/Intel/Graviton instances. Buckle up for a turbo boost to your development workflow!
This solution is greatly inspired by AWS's blog post on using Cloud9 with VS Code. We've repurposed and enhanced the approach to use EC2 instead of Cloud9, while injecting a bit of automation. 😉

## 💡 Solution Overview: Your IDE on Steroids

This setup is like giving your VS Code a dose of super-soldier serum:

💪 Flex with EC2 muscle
🌐 Code from anywhere (yes, even that cool coffee shop)
💰 Keep your wallet happy with Graviton's cost-efficiency
🔒 Fort Knox-level security without the hassle of open ports

## 🛠️ Prerequisites: Gear Up

Before we dive into the code, make sure you've got:

1. AWS account (with the right superpowers, err... permissions)
2. VS Code installed on your trusty local machine
3. AWS CLI configured and ready to roll
4. An SSH client that plays nice with OpenSSH
5. Your personal SSH key pair (your digital ID badge)
6. The `ssm-proxy-go` executable (our secret weapon, more on this later)

## 🏗️ Let's Build This Thing

1. Power Up VS Code: Install the "Remote - SSH" extension. It's like giving VS Code x-ray vision into the cloud.
2. Smooth Operator: Grab the Session Manager plugin for AWS CLI. Think of it as your VIP pass to the AWS club.
3. Key to the Kingdom: Generate your SSH key pair:

```bash
cd ~/.ssh
ssh-keygen -b 4096 -C 'vscode-remote-ssh' -t rsa -f id_rsa-ide
```

4. Config Magic: Set up your SSH config (~/.ssh/config) like a boss:

```bash
Host ide
    IdentityFile ~/.ssh/id_rsa-ide
    User ubuntu
    HostName vscode-host
    ProxyCommand sh -c "~/.ssh/ssm-proxy-go %h 22 myprofile ap-south-1 m7g.xlarge my-vpc ~/.ssh/id_rsa-ide.pub"

Host ide-x86
    IdentityFile ~/.ssh/id_rsa-ide
    User ubuntu
    HostName vscode-host
    ProxyCommand sh -c "~/.ssh/ssm-proxy-go %h 22 myprofile ap-south-1 m5.xlarge my-vpc ~/.ssh/id_rsa-ide.pub"
```

5. The Secret Sauce: Place the `ssm-proxy-go` executable in a directory that's in your system's PATH (e.g., /usr/local/bin on macOS/Linux). or in `.ssh` folder

```bash
OS=$(uname | tr '[:upper:]' '[:lower:]'); ARCH=$(uname -m); ARCH=${ARCH/x86_64/amd64}; ARCH=${ARCH/aarch64/arm64}; ARCH=${ARCH/i386/386}; VERSION=$(curl -s https://api.github.com/repos/alphacenturai/vscode-ec2-integration/releases/latest | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'); wget -O ~/.ssh/ssm-proxy-go "https://github.com/alphacenturai/vscode-ec2-integration/releases/download/${VERSION}/ssm-proxy-go-${OS}-${ARCH}" && chmod +x ~/.ssh/ssm-proxy-go
```

6. The Final Leap: Connect VS Code to your cloud instance and watch the magic happen! 🎩✨

## 🕹️ What This Bad Boy Does

1. 🕵️ Plays detective, checking if your instance exists
2. 🎭 Sets the stage with IAM roles and security groups
3. 🚀 Launches your EC2 instance into the cloud
4. 🛠️ Installs the cool kids (necessary software) and rolls out the red carpet (SSH access)
5. 🔄 Manages your instance's lifecycle like a helicopter parent
6. 🔐 Establishes connections so secure, they'd make a spy jealous

## 🧠 For the Nerds: Technical Deep Dive

The `ssm-proxy-go` program is written in Go and leverages the AWS SDK for Go to automate the process of setting up and connecting to an Amazon EC2 Graviton instance. Here's a detailed breakdown of its structure and functionality:

### Main Package and Imports

```go
package main

import (
    // Standard library imports
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

    // AWS SDK imports
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/ec2"
    "github.com/aws/aws-sdk-go-v2/service/ec2/types"
    "github.com/aws/aws-sdk-go-v2/service/iam"
    "github.com/aws/aws-sdk-go-v2/service/ssm"
    ssmTypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)
```

The program uses a mix of standard library packages and AWS SDK packages to handle various operations.

### Configuration Structure

```go
type Config struct {
    InstanceName     string
    Port             string
    AwsProfile       string
    AwsRegion        string
    InstanceType     string
    VpcName          string
    SshPublicKeyPath string
    ManagedPolicyArn string
}
```

This struct holds the configuration for the EC2 instance setup, including AWS settings and instance details.

### Main Function

The main function serves as the entry point and orchestrates the entire process:

1. Parses command-line flags and arguments
2. Sets up AWS configuration
3. Creates necessary AWS service clients (EC2, IAM, SSM)
4. Calls various functions to set up and manage the EC2 instance

### Key Functions

1. **createOrUpdateInstanceRole**: Manages IAM role creation and policy attachment.
2. **getLatestAmiID**: Queries EC2 to find the latest Ubuntu AMI for ARM64.
3. **getVpcID** **and** **getSubnetID**: Retrieve network configuration details.
4. **createOrUpdateSecurityGroup**: Manages security group creation and rule configuration.
5. **createUserData**: Generates a base64-encoded user data script for instance initialization.
6. **findOrCreateInstance**: Checks for an existing instance or creates a new one.
7. **waitForInstanceOnline**: Polls the instance status until it's ready.
8. **startSSMSession**: Initiates an SSM session for SSH access.

### Error Handling and Retries

The code implements robust error handling and retry mechanisms:

```go
for attempt = 0; attempt < maxRetries; attempt++ {
    resp, err := ssmClient.StartSession(ctx, input)
    if err != nil {
        if isTargetNotConnectedError(err) {
            log.Printf("Instance %s is not connected. Retrying...", instanceID)
            time.Sleep(time.Duration(attempt) * time.Second)
            continue
        }
        log.Fatalf("Failed to start SSM session: %v", err)
    }
    // ... rest of the function
}
```

### Concurrency and Context

The program uses Go's context package for managing timeouts and cancellations:

```go
ctx := context.TODO()
```

While this example uses a blank context, in production, you'd typically use a context with timeout or cancellation capabilities.

By leveraging Go's concurrency features, robust standard library, and the powerful AWS SDK, this program creates a seamless bridge between local development environments and cloud-based compute resources. It enables developers to harness the power of EC2 Graviton instances within their familiar VS Code environment, all while maintaining security best practices and optimizing for cost-efficiency.
