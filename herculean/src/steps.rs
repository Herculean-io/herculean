//! Step vocabulary and ordering rules, ported from the Iolaus solver
//! (`problem_statement.md` operation table, `code/main.py` F/R/V_ORDER).
//! New operations are added only by a recorded decision (ADR); ADR 0002 adds
//! the access operations and ADR 0003 the schema-drift operations, in that
//! order after the solver's in each phase.

use serde::Serialize;

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Phase {
    Finding,
    Remediation,
    Verification,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum State {
    Present,
    Active,
    Disabled,
    Blocked,
    Absent,
    Redacted,
    Anonymized,
    Restricted,
    Reconciled,
}

/// Declaration order is the solver's order: FINDING ops, then REMEDIATION, then
/// VERIFICATION, each in F_ORDER / R_ORDER / V_ORDER sequence. `Ord` follows it.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Operation {
    ReportRemainingRecord,
    ReportExposedPii,
    ReportActiveDataFlow,
    ReportRestoreRisk,
    ReportExcessAccess,
    ReportSchemaDrift,
    DisableDataFlow,
    BlockRestore,
    DeleteRecord,
    RedactRecord,
    AnonymizeRecord,
    RestrictAccess,
    ReconcileSchema,
    VerifyRecordAbsent,
    VerifyRecordPresent,
    VerifyRecordRedacted,
    VerifyRecordAnonymized,
    VerifyDataFlowDisabled,
    VerifyRestoreBlocked,
    VerifyAccessRestricted,
    VerifySchemaReconciled,
}

impl Operation {
    pub fn phase(self) -> Phase {
        use Operation::*;
        match self {
            ReportRemainingRecord
            | ReportExposedPii
            | ReportActiveDataFlow
            | ReportRestoreRisk
            | ReportExcessAccess
            | ReportSchemaDrift => Phase::Finding,
            DisableDataFlow | BlockRestore | DeleteRecord | RedactRecord | AnonymizeRecord
            | RestrictAccess | ReconcileSchema => Phase::Remediation,
            VerifyRecordAbsent
            | VerifyRecordPresent
            | VerifyRecordRedacted
            | VerifyRecordAnonymized
            | VerifyDataFlowDisabled
            | VerifyRestoreBlocked
            | VerifyAccessRestricted
            | VerifySchemaReconciled => Phase::Verification,
        }
    }

    /// Each operation has exactly one state.
    pub fn state(self) -> State {
        use Operation::*;
        match self {
            ReportRemainingRecord | ReportExposedPii | ReportSchemaDrift | VerifyRecordPresent => {
                State::Present
            }
            ReportActiveDataFlow | ReportRestoreRisk | ReportExcessAccess => State::Active,
            DisableDataFlow | VerifyDataFlowDisabled => State::Disabled,
            BlockRestore | VerifyRestoreBlocked => State::Blocked,
            DeleteRecord | VerifyRecordAbsent => State::Absent,
            RedactRecord | VerifyRecordRedacted => State::Redacted,
            AnonymizeRecord | VerifyRecordAnonymized => State::Anonymized,
            RestrictAccess | VerifyAccessRestricted => State::Restricted,
            ReconcileSchema | VerifySchemaReconciled => State::Reconciled,
        }
    }
}

/// The vocabulary spelling (`DISABLE_DATA_FLOW`), as serialized.
impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.serialize(f)
    }
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct Step {
    pub step_no: usize,
    pub phase: Phase,
    pub system_id: String,
    pub resource_id: String,
    pub operation: Operation,
    pub state: State,
    /// Catalog object for a finding; empty for proposed remediation and future verification.
    pub evidence_id: String,
}

impl Step {
    pub fn new(
        step_no: usize,
        operation: Operation,
        system_id: &str,
        resource_id: &str,
        evidence_id: &str,
    ) -> Step {
        Step {
            step_no,
            phase: operation.phase(),
            system_id: system_id.into(),
            resource_id: resource_id.into(),
            operation,
            state: operation.state(),
            evidence_id: evidence_id.into(),
        }
    }
}

/// A remediation: its FINDING, REMEDIATION and VERIFICATION operations.
/// Steps run in that phase order (the solver's `order_steps` rule: phase, then
/// operation order, then system_id, then resource_id); a finding has one of each.
pub type Treatment = [Operation; 3];

pub const DELETE: Treatment = [
    Operation::ReportRemainingRecord,
    Operation::DeleteRecord,
    Operation::VerifyRecordAbsent,
];
pub const DISABLE: Treatment = [
    Operation::ReportActiveDataFlow,
    Operation::DisableDataFlow,
    Operation::VerifyDataFlowDisabled,
];
pub const RESTRICT: Treatment = [
    Operation::ReportExcessAccess,
    Operation::RestrictAccess,
    Operation::VerifyAccessRestricted,
];
pub const RECONCILE: Treatment = [
    Operation::ReportSchemaDrift,
    Operation::ReconcileSchema,
    Operation::VerifySchemaReconciled,
];
