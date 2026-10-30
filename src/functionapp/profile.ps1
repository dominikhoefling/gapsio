# Runs on every cold start of the Function App.
# Deliberately lean: no Az modules, all calls use REST with the managed identity.
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'
