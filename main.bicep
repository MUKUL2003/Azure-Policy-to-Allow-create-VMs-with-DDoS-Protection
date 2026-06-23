/*
  ============================================================
  Azure Policy – DDoS Protection Standard on Virtual Networks
  ============================================================
*/

targetScope = 'subscription'

// ─── Parameters (all values supplied via parameters.json) ────────────────────

@description('Unique name (slug) for the policy definition.')
param policyName string

@description('Human-readable display name shown in the Azure Portal.')
param policyDisplayName string

@description('Detailed description of what the policy enforces.')
param policyDescription string

@description('Portal category under which the policy is grouped.')
param policyCategory string

@description('Semantic version label for the policy definition.')
param policyVersion string

@description('Default effect when the policy is not overridden at assignment time.')
@allowed(['Audit', 'Deny', 'Disabled'])
param policyEffect string

@description('List of effects that operators are allowed to choose from.')
param allowedEffects array

@description('Unique name (slug) for the policy assignment.')
param assignmentName string

@description('Human-readable display name for the policy assignment.')
param assignmentDisplayName string

@description('Description for the policy assignment.')
param assignmentDescription string

@description('Enforcement mode for the assignment: Default (enforced) or DoNotEnforce (audit only).')
@allowed(['Default', 'DoNotEnforce'])
param assignmentEnforcementMode string

@description('Message surfaced to users when their resource is flagged as non-compliant.')
param nonComplianceMessage string

@description('Azure region used for resource deployments if needed.')
param location string

// ─── Load policy rule from external JSON ─────────────────────────────────────

var policyRuleJson = loadJsonContent('policy-rule.json')

// ─── Policy Definition ───────────────────────────────────────────────────────

resource ddosPolicyDefinition 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: policyName
  properties: {
    displayName: policyDisplayName
    description: policyDescription
    policyType: 'Custom'
    mode: 'All'
    metadata: {
      category: policyCategory
      version: policyVersion
    }
    parameters: {
      effect: {
        type: 'String'
        metadata: {
          displayName: 'Effect'
          description: 'The effect determines what happens when the policy rule is evaluated to match.'
        }
        allowedValues: allowedEffects
        defaultValue: policyEffect
      }
    }
    policyRule: policyRuleJson
  }
}

// ─── Policy Assignment ───────────────────────────────────────────────────────

resource ddosPolicyAssignment 'Microsoft.Authorization/policyAssignments@2023-04-01' = {
  name: assignmentName
  properties: {
    displayName: assignmentDisplayName
    description: assignmentDescription
    policyDefinitionId: ddosPolicyDefinition.id
    enforcementMode: assignmentEnforcementMode
    parameters: {
      effect: {
        value: policyEffect
      }
    }
    nonComplianceMessages: [
      {
        message: nonComplianceMessage
      }
    ]
  }
}

// ─── Outputs ─────────────────────────────────────────────────────────────────

@description('Resource ID of the created policy definition.')
output policyDefinitionId string = ddosPolicyDefinition.id

@description('Resource ID of the created policy assignment.')
output policyAssignmentId string = ddosPolicyAssignment.id

@description('Current enforcement effect in use.')
output effectInUse string = policyEffect
