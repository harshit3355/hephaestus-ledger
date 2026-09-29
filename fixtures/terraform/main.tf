# Synthetic AI-inference deployment, modelled with the built-in terraform_data resource so that
# `terraform init/plan/apply` need no provider download and no cloud account. plan.json and
# state.json next to this file are real Terraform output; the benchmark substitutes per-release
# `input` values into these shapes. Regenerate (from this directory):
#   terraform init && terraform plan -out=tfplan && terraform show -json tfplan > plan.json
#   terraform apply tfplan && terraform show -json > state.json
# then delete .terraform/, tfplan, terraform.tfstate*.

variable "image" {
  default = "registry.example.test/inference@sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

resource "terraform_data" "workload_identity" {
  input = {
    name      = "id-inference-prod"
    client_id = "00000000-0000-4000-8000-000000000001"
    roles     = ["Cognitive Services OpenAI User"]
  }
}

resource "terraform_data" "container_app" {
  input = {
    image              = var.image
    identity_client_id = terraform_data.workload_identity.input.client_id
    ingress            = "internal"
    min_replicas       = 2
  }
}

resource "terraform_data" "model_deployment" {
  input = {
    provider      = "azure-openai"
    endpoint      = "https://inference.example.test/"
    model_id      = "gpt-4o"
    model_version = "2024-11-20"
  }
}
