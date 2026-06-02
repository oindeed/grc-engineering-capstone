# compliant-gcs-bucket

A Terraform module that provisions a GCS bucket with the security floor baked in.
Consumers set business config (project, environment, retention, names). The module
enforces the controls below and exposes a compliance_attestation output as evidence.

## Controls enforced

- SC-12  Cryptographic key establishment: customer-managed KMS keyring and key.
- SC-13  Cryptographic protection: CMEK on the bucket, 90-day key rotation.
- SC-28  Protection at rest: bucket encrypted with the CMEK above.
- AC-3   Access enforcement: uniform bucket-level access, public access prevention enforced.
- AU-11  Audit record retention: object versioning plus a retention policy.
- CM-6   Configuration settings: four required labels merged on top of any consumer labels.

## Inputs

See variables.tf. Compliance-relevant settings are hardcoded in main.tf and are not exposed as inputs.

## Outputs

- bucket_url, bucket_self_link, kms_key_id
- compliance_attestation: machine-readable proof of the controls above
