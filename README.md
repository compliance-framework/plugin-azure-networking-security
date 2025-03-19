# Plugin Azure Networking Security

## Assumptions

- That the agent running this plugin has access to the classic Azure env vars in order to use SDK methods
- There is a set of policies specfically scoped to Azure that the config in the agent is pointing to
- Ensure you set AZURE_SUBSCRIPTION_ID as an env var before you run the agent
