# Golden VM Image Packer Config and Pipeline

[Packer](https://www.packer.io/intro) is an open source tool for creating identical machine images for multiple platforms from a single source configuration. Packer is lightweight, runs on every major operating system, and is highly performant, creating machine images for multiple platforms in parallel.

Packer does **not** replace configuration management like Chef or Puppet. In fact, when building images, Packer is able to use tools like Chef or Puppet to install software onto the image.

Packer also does not have a mechanism for managing state and/or deleting old images that have been created through packer (unless they are the same exact image name). A separate cleanup job needs to be configured

## Variable Files

### locals.pkr.hcl
Local variables that would be the same no matter what SDLC the image is built for.

| Local Variable | Description           |
| -------------- | --------------------- |
| vm_tags        | VM tags for targeting |

### variables.pkr.hcl

| Variable          | Type   | Description                                                                    |
| ----------------- | ------ | ------------------------------------------------------------------------------ |
| project_id        | string | The project ID that will be used to launch instances and store images.         |
| zone              | string | The zone in which to launch the instance used to create the image.             |
| environment       | string | Associated Software Development Lifecycle Environment                         |
| commit_sha        | string | Associated commit hash for tracking; Will be provided by Jenkins pipelines.    |
| skip_create_image | bool   | Skip creating the image. Useful for setting to true during a build test stage. |
| gcp_creds         | string | Key JSON of SA that has proper roles to run Packer                             |
| vm_subnet         | string | Subnet for which to launch Compute Instances for Packer building               |

refer to [examples](./examples) for sample values used.


Use Packers build command line option [-only](https://www.packer.io/docs/commands/build#only-foo-bar-baz) to build individual images for ex: "rhel8.*", when developing or testing locally.
For example: packer build -var-file="examples/variables.pkrvars.hcl" -only "rhel8.*" .

Windows Example -Only Filters:

* Build all Windows Only
  * windows-builder.googlecompute.windows*
  * windows-builder.*.windows*
* Build all SQL Only
  * windows-builder.googlecompute.*sql*
  * windows-builder.*.*sql*


## Pipelines

**pipelines/packerPipeline.jenkinsfile**
Jenkinsfile for pipeline that will run a parameterized packer validation, build, and push of VM images described in `*images*.pkr.hcl` files.

## Infrastructure Terraform

**terraform/**
This terraform configuration generates necessary Service Accounts, Workload Identity Modification, Firewall Rules, and GCP APIs unique to allowing the Packer Pipeline to validate, build (which includes having to spin up and tear down a Compute Instance), and push the VM image to the target project.



## Steps to establish end-to-end packer setup (per each SDLC environment if necessary)

1. (If not already done), go to the Jenkins server and create two Pipelines. One for `specialTFPKRPipeline.jenkinsfile` and another for `packerPipeline.jenkinsfile`.
1. Write/modify Terraform manifests in `./terraform/manifests`
1. Run the Jenkins pipeline associated with `specialTFPKRPipeline.jenkinsfile` with proper parameters.
1. (If VM Images need to be added/removed/updated) Modify the `*.pkr.hcl` image configurations.
1. Run the Jenkins pipeline associated with `packerPipeline.jenkinsfile` with proper parameters.
