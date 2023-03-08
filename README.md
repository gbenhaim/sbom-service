# SBOM Service

POC for a service that allows extracting SBOM from container registries.

## Usage example

```bash
go run . &

curl localhost:8080/sbom/quay.io/redhat-appstudio/user-workload:initial-build-5b3cd-1678046199

```


