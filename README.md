# Attested OHTTP Server

This repository is an implementation of an attested OHTTP server for [Azure AI Confidential Inferencing](https://techcommunity.microsoft.com/blog/azure-ai-services-blog/azure-ai-confidential-inferencing-preview/4248181). 
Together with [attested OHTTP client](https://github.com/microsoft/attested-ohttp-client) and a [transparent 
key management service](https://github.com/microsoft/azure-transparent-kms), it enables secure communication between clients and [Confidential GPU VMs](https://) serving Azure AI models using [chunked OHTTP](https://www.ietf.org/archive/id/draft-ohai-chunked-ohttp-01.html). Learn more here. 

- [Azure AI Confidential Inferencing: Technical Deep Dive](https://techcommunity.microsoft.com/blog/azureconfidentialcomputingblog/azure-ai-confidential-inferencing-technical-deep-dive/4253150)

## Building

The repo supports build and development using GitHub Codespaces and devcontainers. The repository includes a devcontainer configuration that installs all dependencies.

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/microsoft/attested-ohttp-server). 

Build the attested OHTTP server container.

```
make build-server-container
```

## Testing

For testing, this repository includes a sample whisper container. 

```
make build-whisper-container
```

Next, clone and build the attested OHTTP client container. 

```
git submodule update --recursive
make build-client-container
```

Finally, run the containers locally
```
make run-server-whisper
```

In a separate terminal,
```
./scripts/service_wait.sh 127.0.0.1:3000
./scripts/service_wait.sh 127.0.0.1:9443
make run-client-container
```

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
