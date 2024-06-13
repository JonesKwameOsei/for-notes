# Deployment Of A Four Tier Appication in Kubernestes
## Overview
This project seeks to deploy a web app which hosts a web CV and Portfolio. The Website is linked to an external RDS managed by AWS. The project utilise AWS Elastic Kubernetes services to orchestrate the containers which were containerised with `Docker`. The AWS EKS and the MySQL RDS resources were deployed and managed by `Terraform`. 

## Project application Stack 
- Terraform: For Infrastructure as Code (IaC)
- Docker: For dockerising web applications
- Kubernestes (AWS EKS): For container orchestration
- Git and GitHub: For source code control
### Create An Amazon Elastic Kubernetes Services (EKS) Cluster
**Terraform** is utilised to build and managed AWS resources for this project. The `Amazon Elastic Kubernetes Service (EKS)` and `MySQL` relational datatbase service come with a cost and managing the build and tear-down with Terraform helps to reduce cost. <p> 
To allow the AWS EKS to create AWS resources on my behalf, I need to create an `IAM role` that EKS can assume. The IAM is also configured in the Terraform set up below:

1. **Create an IAM Role**: 
Create a file locally called trust.json in my project working directory with the following policy:

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```
### Setup Terraform Configurations 🚀🔍
1. Providers.tf
```
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "eu-west-1"
}
```
2. data.tf
```
data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

# get vpc data
data "aws_vpc" "default" {
  default = true
}
#get public subnets for cluster
data "aws_subnets" "public" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}
```
3. local.tf
```
locals {
  name             = format("%s-%s", var.name, "vpc")
  short_region     = "euw2"
  resource_name    = format("%s-%s", var.name, local.short_region)
  aws_ssm_username = format("/%s/%s/%s", var.name, local.short_region, "username")
  aws_ssm_password = format("/%s/%s/%s", var.name, local.short_region, "password")
}
```

4. variables.tf
```
# Variables configirations 
# The following are the default values for the configuration variables in main.tf and ssm.tf
# Variables configirations 
# The following are the default values for the configuration variables

variable "name" {
  type        = string
  description = "name for resources"
  default     = "jones"
}

variable "instance_type" {
  type        = list(string)
  description = "Type of EC2 Instance to run EKS on"
  default     = ["t2.medium"]
}

variable "ec2_scaling" {
  type        = list(number)
  description = "Number of EC2 instances to run in the EKS cluster"
  default     = [3, 5]
}

variable "db_name" {
  type        = string
  description = "Name of the RDS database"
  default     = "jones-db"
}

variable "storage" {
  type        = number
  description = "Storage size for RDS database"
  default     = 20
}

variable "engine" {
  type        = string
  description = "Database engine"
  default     = "mysql"
}

variable "engine_version" {
  type        = string
  description = "Database engine version"
  default     = "8.0"
}

variable "instance_class" {
  type        = string
  description = "Instance class for RDS database"
  default     = "db.t3.micro"
}

variable "db_username" {
  type        = string
  description = "Username for RDS database"
  default     = "jones"
}

variable "password" {
  type        = string
  description = "Password for RDS database"
  default     = "jones_1234"
}

variable "parameter_group_name" {
  type        = string
  description = "Parameter group name for RDS database"
  default     = "default.mysql8.0"
}

variable "skip_final_snapshot" {
  type        = bool
  description = "Skip final snapshot"
  default     = true
}
```
5. main.tf
```
# Resources configirations 
# The following are the configurations for Terraform to create resources in AWS

# create the IAM role for EKS
resource "aws_iam_role" "myk8s_role" {
  name               = "Myk8sRole"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

# Attach the EKS service policy to the role
resource "aws_iam_role_policy_attachment" "myk8s-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.myk8s_role.name
}

#cluster provision
resource "aws_eks_cluster" "mywebsite_cluster" {
  name     = "k8s-web-cluster"
  role_arn = aws_iam_role.myk8s_role.arn

  vpc_config {
    subnet_ids = data.aws_subnets.public.ids
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
  # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role_policy_attachment.myk8s-AmazonEKSClusterPolicy,
  ]
}

# Create Node Grroup
resource "aws_iam_role" "myk8s-node" {
  name = "myk8s-node-group-cloud"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

# Attach Policies
resource "aws_iam_role_policy_attachment" "myk8sNode-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.myk8s-node.name
}

resource "aws_iam_role_policy_attachment" "myk8sCNI-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.myk8s-node.name
}

resource "aws_iam_role_policy_attachment" "myk8sECR-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.myk8s-node.name
}

# create node group
resource "aws_eks_node_group" "myk8s_node_grp" {
  cluster_name    = aws_eks_cluster.mywebsite_cluster.name
  node_group_name = "k8s-website_Node-cloud"
  node_role_arn   = aws_iam_role.myk8s-node.arn
  subnet_ids      = data.aws_subnets.public.ids

  scaling_config {
    desired_size = var.ec2_scaling[0]
    max_size     = var.ec2_scaling[1]
    min_size     = var.ec2_scaling[0]
  }
  instance_types = var.instance_type

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.myk8sNode-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.myk8sCNI-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.myk8sECR-AmazonEC2ContainerRegistryReadOnly,
  ]
}

# Create mysql RDS as external db
resource "aws_db_instance" "default" {
  allocated_storage    = var.storage
  db_name              = var.name
  engine               = var.engine
  engine_version       = var.engine_version
  instance_class       = var.instance_class
  username             = aws_ssm_parameter.db_username.value
  password             = aws_ssm_parameter.db_password.value
  parameter_group_name = var.parameter_group_name
  skip_final_snapshot  = var.skip_final_snapshot
}
```

6. **Output.tf**:  The purpose of Terraform outputs is to provide an easy way to retrieve important information (such as resource IDs or ARNs) after deploying infrastructure. Outputs makes it possible to programmatically access these values for further use, such as integrating with other tools or scripts. In a new file named, outputs.tf, add:
```
# Output for IAM Role ID and ARN
output "iam_role_id" {
  value = aws_iam_role.myk8s_role.id
}

output "iam_role_arn" {
  value = aws_iam_role.myk8s_role.arn
}

# Output for EKS Node Group ID and ARN
output "eks_node_group_id" {
  value = aws_eks_node_group.myk8s_node_grp.id
}

output "eks_node_group_arn" {
  value = aws_eks_node_group.myk8s_node_grp.arn
}

# Outputs for EKS Cluster ID and ARN
output "eks_cluster_id" {
  value = aws_eks_cluster.mywebsite_cluster.id
}

output "eks_cluster_arn" {
  value = aws_eks_cluster.mywebsite_cluster.arn
}

# Output for MySQL RDS
output "rds_instance_id" {
    value = aws_db_instance.defaut.id
}
```
7. **Create SSM Parameters**:
We will obscure 🛡️🔐 our RDS login details with secrets secured in AWS Systems Manager Parameter Store. The Parameter store enables secrets to be stored in Secrets Manager. To do this, we have to:
   - Define two `SSM parameters`: one for the *username* and another for the *password*.
   - Use Terraform to create them.<p>
To securely store the RDS database username and password in AWS Systems Manager (SSM) Parameter Store using Terraform, We will:
   - Create a new `ssm.tf` file and add the following Terraform code:
```
# Creating a RDS Secrets with SSM parameter store. 
resource "aws_ssm_parameter" "db_username" {
  name  = "${local.aws_ssm_username}/username"
  type  = "SecureString"
  value = var.db_username
}

resource "aws_ssm_parameter" "db_password" {
  name  = "${local.aws_ssm_password}/password"
  type  = "SecureString"
  value = var.password
}
```
### Deploying AWS Resorces with Terraform 
Having configured Terraform, it at this point knows the resources it needs to create. To create the resources, we will run the following terraform commands. 
```
terraform init
Terradorm validate
```
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/5649be41-7afb-465f-8276-199352bee376)<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/1ec3d775-b9e1-4417-8f90-733e1d42fc83)<p>

```
terraform plan -out eks_rds_plan
```
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/742c15fc-9b3a-48d7-bc52-2b184ac5a180)<p>

```
terraform apply eks_rds_plan
```
**Outputs after applying the plan**:<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/f6dd7112-abef-443c-839c-878fd24d6f4d)<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/df88e63c-c546-4e98-bea7-69a6e4c6f30e)<p>

Now we will head to the AWS console to verify if the `Terraform` did exactly what we declared. <p>
The EKS Cluster is created:<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/aea22bc3-88d3-4609-9e9a-51f671d4eeec)<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/77626baf-a276-469c-8e1b-127cd9b9e1ac)<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/f9adacc4-9008-48b3-bfc1-2d85c160afd2)<p>
The `Nodes` and `Node Groups`:<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/e7278f54-d64e-4c1d-8924-3370b6faddb3)<p>

Amazon ECR Repository:<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/2058997f-d2b9-4447-a0a9-28b0a8edf630)<p>
The `IAM Role`:<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/31a31326-61a3-4d6d-85b0-53fd003aec84)<p>
Amazon RDS: MySQL and EC2 Instance connect:<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/43b88970-6932-4230-81c4-ca952607093d)<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/f029b390-59a7-4bb3-8782-4efb699c6e5c)<p>

MySQL `secrets` in Parameter Store:<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/087c3e6d-ca70-450e-90e6-bd23e8f812d6)<p>
**Accessing Parameters**:
   - To retrieve the stored values, use the AWS SDK or CLI with appropriate permissions.
   - Example CLI command to retrieve the username:
     ```
     aws ssm get-parameter --name "/jones/euw1/endpoint/endpoint" --with-decryption
     ```
### Connect to the EC2 Instance
We will connect to the EC2 DB Instance Connect Via SSH. 
**Connect to  the instance***.
```
ssh -i "MyK8sKeyPair.pem" ubuntu@ec2-34-240-184-79.eu-west-1.compute.amazonaws.com
```
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/36d5d3c5-17d9-4261-8020-66f176b79e39)

Or, in windows via MobaXterm:
```
ssh -i "C:\Users\KWAME\.ssh\id_edi56432" ubuntu@34.240.184.79
```
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/937db57a-0faa-4aeb-b517-492ec01049b8)<p>

### Connect the EC2 Instance to the DB Instance

```
mysql -h endpoint -P 3306 -u admin -p
```
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/7d63618f-7065-462d-a0dd-57ee42deaa85)<p>

Now that we have connected the EC2 instance to the DB instance, let's run some basic commands:
```
SELECT CURRENT_TIMESTAMP;

SHOW DATABASES;
```
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/f1de560d-b548-4bd6-99ac-9b372767fbee)<p>

3. 
### Manage EKS Cluster
The cluster can be managed with `kubectl`. We have to update the `kubeconfig file by running:
```
aws eks update-kubeconfig --name k8s-web-cluster
```
To test this, we will check if the cluster in within our contest locally:
```
kubectx
```
Now let's get the nodes running:
```
kubctl get nodes
```
**Outputs**:<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/c2337af8-4761-49b8-878f-cbe803f83abc)
The name of the cluster is too long and we can renamed this:
```
kubectx eks_cluster=arn:aws:eks:eu-west-1:194626909496:cluster/k8s-web-cluster
```
Cluster has been remaned and we can see the new name by re-running:
```
kubectx
```
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/89d33cdf-0faf-46f3-ab03-7b35a8153ba8)<p>
Cluster is ready to be worked with locally. It has been populated in `Lens`.<p>
 ![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/084c67a0-fb80-4ff6-93a9-958b37a02d68)<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/cccb77a3-b12f-44a0-bad2-cf7567ffe3ce)<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/ac050485-d4fb-4ff5-999c-424eec8b9f5b)<p>

### Install Ingress Controller
To create the ingress controller, we will run:
```
helm upgrade --install ingress-nginx ingress-nginx --repo https://kubernetes.github.io/ingress-nginx  --namespace ingress-nginx --create-namespace \
  --set-string controller.service.annotations."service\.beta\.kubernetes\.io/aws-load-balancer-type"="nlb"
```
Ingress controller is installed:<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/e16d1b32-cfe2-4ef0-ab79-ed86deca86d9)<p>
**Output**:
```
Release "ingress-nginx" does not exist. Installing it now.
NAME: ingress-nginx
LAST DEPLOYED: Sat Jun  8 19:12:03 2024
NAMESPACE: ingress-nginx
STATUS: deployed
REVISION: 1
TEST SUITE: None
NOTES:
The ingress-nginx controller has been installed.
It may take a few minutes for the load balancer IP to be available.
You can watch the status by running 'kubectl get service --namespace ingress-nginx ingress-nginx-controller --output wide --watch'

An example Ingress that makes use of the controller:
  apiVersion: networking.k8s.io/v1
  kind: Ingress
  metadata:
    name: example
    namespace: foo
  spec:
    ingressClassName: nginx
    rules:
      - host: www.example.com
        http:
          paths:
            - pathType: Prefix
              backend:
                service:
                  name: exampleService
                  port:
                    number: 80
    tls:
      - hosts:
        - www.example.com
        secretName: example-tls

If TLS is enabled for the Ingress, a Secret containing the certificate and key must also be provided:

  apiVersion: v1
  kind: Secret
  metadata:
    name: example-tls
    namespace: foo
  data:
    tls.crt: <base64 encoded cert>
    tls.key: <base64 encoded key>
  type: kubernetes.io/tls
```
Viewing helm deployment in Lens:<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/bfc8cdd0-5ad8-4b8b-b6bb-3b3009682736)<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/1d2e9030-7158-4a95-a64a-c020120ce400)<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/9902d22e-2deb-449e-8416-7f6029ddbca9)<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/de3c14ff-46cf-4551-8a82-9bc56748160a)<p>

Loadbalancer created automatically by AWS. This can be seen in Lens under services:<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/b88513ea-b709-476c-80c6-edf839c882e3)<p>
Same has been created in the AWS console:<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/e6f192c3-3a12-4cbc-bae9-2f66b2b97acf)<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/cbf81199-57ff-45da-84cd-d97a1d0d83ee)<p>
We can get the service locally by running:
```
kubectl get service --namespace ingress-nginx
```
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/d1ebe85c-f146-4ac3-b8b8-d76196f09cb9)<p>
or change the namespace by running:
```
kubens
kubens ingress-inginx 
```
Outputs:
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/53dac783-ae61-493d-aca3-b8215b309dff)

To watch the status running locally, we will run:
```
kubectl get service --namespace ingress-nginx ingress-nginx-controller --output wide --watch
```
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/de67c3df-3476-4c5d-bc9a-f234a2c9a1b7)<p>

### Install Cert Manager and Issuer 🔐
Cert-Manager and Issuers simplify certificate management, enhance security, and automate the entire SSL/TLS lifecycle in Kubernetes.  <p>
They also automates certificate handling, and ensures smooth communication in Kubernetes clusters. <p> 
**Create Cert Manager**:
```
helm repo add jetstack https://charts.jetstack.io --force-update
helm repo update
helm install \
  cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version v1.14.5 \
  --set installCRDs=true
```
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/6ca4a576-a648-47e4-a0cd-191f7515d658)<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/a31d0809-768d-4b65-bf07-d31dfc1fdc97)<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/c3c92777-f650-4500-8a97-6fb17b701fa0)


In order to begin issuing certificates, we will need to set up a `ClusterIssuer` or `Issuer resource`. <br /> For this project, we will use `letsencrypt-staging' issuer`.

**Create a Cert Issuer** 🛡️.
Create a new yml file and name it. Named mine, production_issuer.yml. Add the following configurations.
```
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    # Email address used for ACME registration
    email: oseikwamejones11@hotmail.com                                   # change to your email
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      # Name of a secret used to store the ACME account private key
      name: letsencrypt-prod-private-key
    # Add a single challenge solver, HTTP01 using nginx
    solvers:
    - http01:
        ingress:
          class: nginx
```
Apply the yml file to create the issuer:
```
kubectl apply -f production_issuer.yml            # Ensure you are in the right directory or add file path 
```
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/c596c794-c284-496f-a194-6b35df460ad6)<p>
To get the `issuer` created, run:
```
kubectl get clusterissuers.cert-manager.io
```
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/b6e12c16-d728-49d0-bedc-9dc752425712)<p>

### Install Metrics Server
```
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
```
Metrics-server created:<p>
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/ce659ca1-4e25-4408-8b6c-735e9c4d6e8e)<p>
Let's get the metrics-server deployed:
```
kubectl get deployment metrics-server -n kube-system
kubectl get pods -n kube-system 
```
![image](https://github.com/JonesKwameOsei/Deployment-of-Four-tier-Achitecture-Project/assets/81886509/0c756f7e-a68d-4ccd-8fdb-6ea75d5f2432)



===Create Database and User===
create database ghost_db; 
```
CREATE USER 'ghost_user'@'%' IDENTIFIED BY 'ghost_password';
GRANT ALL PRIVILEGES ON ghost_db.* TO 'ghost_user'@'%';
FLUSH PRIVILEGES;
```








