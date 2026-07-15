import Testing
import Foundation
import CryptoKit
@testable import SallyportVault

@Suite("VaultCrypto — record sealing (v2: sid/version/domain)")
struct VaultCryptoTests {
    let dek = SymmetricKey(size: .bits256)
    let sid = "6f0a1f2e-aaaa-bbbb-cccc-000000000001"

    @Test("seal → open round-trips the exact bytes")
    func roundTrip() throws {
        let pt = Data("sk_live_never_leak_42".utf8)
        let blob = try VaultCrypto.seal(pt, dek: dek, sid: sid, version: 1, domain: VaultCrypto.valueDomain)
        #expect(blob != pt)   // it's actually encrypted
        let out = try VaultCrypto.open(blob, dek: dek, sid: sid, version: 1, domain: VaultCrypto.valueDomain)
        #expect(out == pt)
    }

    @Test("a record can't be moved to another sid/version/domain (AAD binds it)")
    func aadBinding() throws {
        let blob = try VaultCrypto.seal(Data("x".utf8), dek: dek, sid: sid, version: 1, domain: "value")
        #expect(throws: (any Error).self) {
            _ = try VaultCrypto.open(blob, dek: dek, sid: "other-sid", version: 1, domain: "value")
        }
        #expect(throws: (any Error).self) {
            _ = try VaultCrypto.open(blob, dek: dek, sid: sid, version: 2, domain: "value")
        }
        // The meta ↔ value domain split: a sealed value can never be decoded as
        // metadata (or vice versa) even for the same sid/version.
        #expect(throws: (any Error).self) {
            _ = try VaultCrypto.open(blob, dek: dek, sid: sid, version: 1, domain: "meta")
        }
    }

    @Test("a different DEK cannot open the record")
    func wrongDEK() throws {
        let blob = try VaultCrypto.seal(Data("x".utf8), dek: dek, sid: sid, version: 1, domain: "value")
        #expect(throws: (any Error).self) {
            _ = try VaultCrypto.open(blob, dek: SymmetricKey(size: .bits256), sid: sid, version: 1, domain: "value")
        }
    }

    @Test("record subkey is deterministic in (dek,sid,version,domain) but distinct per slot")
    func subkeyDerivation() {
        let k1 = VaultCrypto.recordKey(dek: dek, sid: "a", version: 1, domain: "value")
        let k1again = VaultCrypto.recordKey(dek: dek, sid: "a", version: 1, domain: "value")
        let k2 = VaultCrypto.recordKey(dek: dek, sid: "a", version: 2, domain: "value")
        let k3 = VaultCrypto.recordKey(dek: dek, sid: "b", version: 1, domain: "value")
        let kMeta = VaultCrypto.recordKey(dek: dek, sid: "a", version: 1, domain: "meta")
        #expect(k1 == k1again)
        #expect(k1 != k2)
        #expect(k1 != k3)
        #expect(k1 != kMeta)
        // The recording key is a separate HKDF domain.
        #expect(VaultCrypto.recordingKey(dek: dek) != k1)
    }

    @Test("two seals of the same plaintext differ (fresh nonce per seal)")
    func freshNonce() throws {
        let pt = Data("same".utf8)
        let a = try VaultCrypto.seal(pt, dek: dek, sid: sid, version: 1, domain: "value")
        let b = try VaultCrypto.seal(pt, dek: dek, sid: sid, version: 1, domain: "value")
        #expect(a != b)
    }

    @Test("blobs (hosts/settings) round-trip and bind to their key")
    func blobs() throws {
        let pt = Data(#"[{"name":"prod-1","addr":"10.0.0.1"}]"#.utf8)
        let blob = try VaultCrypto.sealBlob(pt, dek: dek, key: "hosts")
        #expect(try VaultCrypto.openBlob(blob, dek: dek, key: "hosts") == pt)
        #expect(throws: (any Error).self) {
            _ = try VaultCrypto.openBlob(blob, dek: dek, key: "settings")
        }
    }

    @Test("recordings seal under the DEK and bind to their filename")
    func recordings() throws {
        let cast = Data("{\"version\":2}\n[0.1,\"o\",\"hello\"]\n".utf8)
        let sealed = try VaultCrypto.sealRecording(cast, dek: dek, filename: "ssh-1.cast.sealed")
        #expect(sealed != cast)
        #expect(try VaultCrypto.openRecording(sealed, dek: dek, filename: "ssh-1.cast.sealed") == cast)
        // Renamed/swapped file → AAD failure.
        #expect(throws: (any Error).self) {
            _ = try VaultCrypto.openRecording(sealed, dek: dek, filename: "ssh-2.cast.sealed")
        }
    }
}
