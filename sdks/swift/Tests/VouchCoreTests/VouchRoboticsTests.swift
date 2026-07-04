import XCTest

@testable import VouchCore

final class VouchRoboticsTests: XCTestCase {
    private let scope = """
        {"maxForceN":80.0,"maxSpeedMps":1.5,"maxSpeedNearHumansMps":0.25,"allowedZones":["cell-3"]}
        """

    private let conformanceCredentials = """
        [{"type":["VerifiableCredential","RobotIdentityCredential"],\
        "credentialSubject":{"id":"did:web:r","make":"Acme","model":"AR-7","serial":"SN-1",\
        "hardwareRoot":{"kind":"TPM"}}},\
        {"type":["VerifiableCredential","ModelProvenanceAttestation"],\
        "credentialSubject":{"id":"did:web:r","vla":{"modelName":"M","weightsHash":"uW",\
        "safetyPolicy":"uP","configHash":"uC"}}},\
        {"type":["VerifiableCredential","PhysicalCapabilityScope"],\
        "credentialSubject":{"id":"did:web:r","physicalScope":{"maxForceN":80.0,"maxSpeedMps":1.5,\
        "maxSpeedNearHumansMps":0.25,"allowedZones":["cell-3"]}}},\
        {"type":["VerifiableCredential","RobotSafetyRecordCredential"],\
        "credentialSubject":{"id":"did:web:r","totalEvents":2,"logHead":"uHEAD"}}]
        """

    func testCheckActionAllowsWithinScope() throws {
        let report = try VouchRobotics.checkAction(
            scopeJson: scope,
            actionJson: "{\"forceN\":10.0,\"speedMps\":0.2,\"nearHumans\":true,\"zone\":\"cell-3\"}"
        )
        XCTAssertTrue(report.contains("\"ok\":true"))
    }

    func testCheckActionRejectsOverSpeedNearHumans() throws {
        let report = try VouchRobotics.checkAction(
            scopeJson: scope,
            actionJson: "{\"speedMps\":1.2,\"nearHumans\":true,\"zone\":\"cell-3\"}"
        )
        XCTAssertTrue(report.contains("\"ok\":false"))
    }

    func testCheckConformanceReportsFullCoverage() throws {
        let report = try VouchRobotics.checkConformance(
            credentialsJson: conformanceCredentials,
            profileId: "eu-ai-act-high-risk"
        )
        XCTAssertTrue(report.contains("\"conforms\":true"))
        XCTAssertTrue(report.contains("\"totalCount\":4"))
    }
}
