import Testing
import Foundation
import CryptoKit
import Security
@testable import SallyportVault

/// The Swift-side SSH signer (agent-signing): the private key never leaves this
/// process. These prove, against real `ssh-keygen` output, that we (a) parse the
/// openssh-key-v1 format and re-derive the SAME public-key blob ssh-keygen wrote,
/// and (b) produce signatures that verify under that public key — for every key
/// type a fleet uses.
@Suite("SSH agent-signing — key parse + sign, all types")
struct SSHKeyTests {

    private struct Fixture {
        let name: String
        let pem: String
        let pubBlobB64: String   // the base64 field from the .pub line (the wire blob)
    }

    // ssh-keygen -t … -N "" (unencrypted openssh-key-v1), one per type.
    private static let fixtures: [Fixture] = [
        Fixture(name: "ed25519", pem: """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACD7h/ZZqiUmzNnzYaRYIrev5Txs+zE2rMN6yA7dS9FKrAAAAJAF/g86Bf4P
        OgAAAAtzc2gtZWQyNTUxOQAAACD7h/ZZqiUmzNnzYaRYIrev5Txs+zE2rMN6yA7dS9FKrA
        AAAEBym//pp6FZ+2w6QefNdl+sIHqX8UoD4q/+8BOE+njHtfuH9lmqJSbM2fNhpFgit6/l
        PGz7MTasw3rIDt1L0UqsAAAABmZpeC1lZAECAwQFBgc=
        -----END OPENSSH PRIVATE KEY-----
        """, pubBlobB64: "AAAAC3NzaC1lZDI1NTE5AAAAIPuH9lmqJSbM2fNhpFgit6/lPGz7MTasw3rIDt1L0Uqs"),

        Fixture(name: "ecdsa-p256", pem: """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
        1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTXKR/yogRbewTUUnZZoNKDhBiVa7oS
        FIqWyht06Er5UXjt93v8SbXwtj0m0FrSHQFPQCTvLA0UYUQeREMKuY1mAAAAoFUvVE1VL1
        RNAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNcpH/KiBFt7BNRS
        dlmg0oOEGJVruhIUipbKG3ToSvlReO33e/xJtfC2PSbQWtIdAU9AJO8sDRRhRB5EQwq5jW
        YAAAAgLAsbBXRrPGj8e92w4KsWka9WcryZb8X6hrOVFzqcN5UAAAAIZml4LXAyNTY=
        -----END OPENSSH PRIVATE KEY-----
        """, pubBlobB64: "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNcpH/KiBFt7BNRSdlmg0oOEGJVruhIUipbKG3ToSvlReO33e/xJtfC2PSbQWtIdAU9AJO8sDRRhRB5EQwq5jWY="),

        Fixture(name: "ecdsa-p384", pem: """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS
        1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQSFmxC3bIs/HHuAQdU7RxqgPPsSAHhr
        bjROXoUDHXWrZRZAX5f+H9hXqpccTijFc1n3AUw2IWt8ZPjQzXmFNo3UfRo7oQ1GhWTI0r
        uTQIIRnQG5mWYylo4mSrCbPpZSxmcAAADYC4xNVAuMTVQAAAATZWNkc2Etc2hhMi1uaXN0
        cDM4NAAAAAhuaXN0cDM4NAAAAGEEhZsQt2yLPxx7gEHVO0caoDz7EgB4a240Tl6FAx11q2
        UWQF+X/h/YV6qXHE4oxXNZ9wFMNiFrfGT40M15hTaN1H0aO6ENRoVkyNK7k0CCEZ0BuZlm
        MpaOJkqwmz6WUsZnAAAAMQCkrWj4DR8cX0kaMF9MQTbu1P3RAAn0wn7KN3CTeuIMeKZDEu
        uLEKmOZxRo4dlotwEAAAAIZml4LXAzODQBAgMEBQYH
        -----END OPENSSH PRIVATE KEY-----
        """, pubBlobB64: "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBIWbELdsiz8ce4BB1TtHGqA8+xIAeGtuNE5ehQMddatlFkBfl/4f2FeqlxxOKMVzWfcBTDYha3xk+NDNeYU2jdR9GjuhDUaFZMjSu5NAghGdAbmZZjKWjiZKsJs+llLGZw=="),

        Fixture(name: "ecdsa-p521", pem: """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS
        1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQBJ6im9krryfq8oeS67yaHeP3DzQjT
        0/mN0hqCCE9yKNImc+F8CZbV/AZfFH31gg94Q/h9QG/F+pypvU3dryO7lQ4AH46HiyOvxW
        WFnJN+81eyIMMqRx7hLiaDPwbYVGWDSg0q/xIpIIrNgOS5aTiiqMEls6ZTHd4m+KB54M6h
        VYeZwZQAAAEImiJDSZoiQ0kAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ
        AAAIUEASeopvZK68n6vKHkuu8mh3j9w80I09P5jdIagghPcijSJnPhfAmW1fwGXxR99YIP
        eEP4fUBvxfqcqb1N3a8ju5UOAB+Oh4sjr8VlhZyTfvNXsiDDKkce4S4mgz8G2FRlg0oNKv
        8SKSCKzYDkuWk4oqjBJbOmUx3eJvigeeDOoVWHmcGUAAAAQgF9b7fYuRWgGufLrkrlV5gR
        fMre/mRcrIk8AhZBaQt9Kj07f90pXtizbhl6MyTtYxzrdqBnFl0uV6CVGxroZozMiwAAAA
        hmaXgtcDUyMQEC
        -----END OPENSSH PRIVATE KEY-----
        """, pubBlobB64: "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAEnqKb2SuvJ+ryh5LrvJod4/cPNCNPT+Y3SGoIIT3Io0iZz4XwJltX8Bl8UffWCD3hD+H1Ab8X6nKm9Td2vI7uVDgAfjoeLI6/FZYWck37zV7IgwypHHuEuJoM/BthUZYNKDSr/Eikgis2A5LlpOKKowSWzplMd3ib4oHngzqFVh5nBlA=="),

        Fixture(name: "rsa-2048", pem: """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
        NhAAAAAwEAAQAAAQEAt5UEvS68HJAETgtEXfL328NX2JdFFjuZOM3S2oqg2jwBKJ+LCtc7
        LvnDlZZ6hCMP6CpUKmUseg5UYYTZEEbSpSjuj00TQETRwAgsioCM0naChW9N7BfMQdaoFC
        inLpTsZWbB17ucHy6nBER6YIDxlnkif+Uq5a2CBwuvDVmMWG5oOdR2YKyrf2dsED+tXFEt
        o2lNiYZy5sseqsqaKa/GJuFvknc7k5ML1JTO6DksFTTbt+9rb5noiD36f9IpF12SETlMX7
        f2vLv+BrThlMlsBoZjTQPf0XvFAs3v9g0cqHpxdScsqU7tnZ8PATwePexuDnr/qo+3POG2
        qZnrk3FZ5wAAA8iyc0/IsnNPyAAAAAdzc2gtcnNhAAABAQC3lQS9LrwckAROC0Rd8vfbw1
        fYl0UWO5k4zdLaiqDaPAEon4sK1zsu+cOVlnqEIw/oKlQqZSx6DlRhhNkQRtKlKO6PTRNA
        RNHACCyKgIzSdoKFb03sF8xB1qgUKKculOxlZsHXu5wfLqcERHpggPGWeSJ/5SrlrYIHC6
        8NWYxYbmg51HZgrKt/Z2wQP61cUS2jaU2JhnLmyx6qypopr8Ym4W+SdzuTkwvUlM7oOSwV
        NNu372tvmeiIPfp/0ikXXZIROUxft/a8u/4GtOGUyWwGhmNNA9/Re8UCze/2DRyoenF1Jy
        ypTu2dnw8BPB497G4Oev+qj7c84bapmeuTcVnnAAAAAwEAAQAAAQEAo2wAf/hudG6vplnZ
        TljP084dES33zkbXqv1uSiVF83+e+G6t88SNZs/oD+2YurALpPypV+Qgp7bB3t3H7Ple4q
        +BTgeqr3eT0IJ2RAUTVvcwUWA32YeFyMYxcWCPEqR3m/zRah4UaJ27B819sxKV/QFweLGk
        cjj2mxcHibbBfKWnTf6lRs0JKadvQr1dDdht6Wb8IMdLnGgEkMBZLOnEnfJX95WzL3ASkh
        ENk4P1w5uD6fsLJaw4tDmsromee6haGHBzBbGeZJWfO2COTtHX9/na19xuMQ42hqFBrXmz
        NjysMlPrqehzYSg3z9cFc8bOyR1tJRZdEnz6uCr7SzslAQAAAIAiYH8lalVJjDCzi+ZKtY
        94s47GAfs9/E1ofaSAIGyxsHJcl/i+A1diCudnMcKOFQMEWHzgVEZ/wFXz4Vk7eDSdvkz+
        z1tdMEqk+XrHb+qYPLWXVHJeEQd06TyOJbfSGp8E/zQaWi+o58UCSqCBkjiCgR03TVl2Ge
        qvyJoN81jL3AAAAIEA9K4Cyl1nwjmKE1dEgxo6+pNVsIvLPlYhMj+cbA7ywwxxJB5XZftq
        JEaQEDQKL2DJOdCcdtYzOgzNsGHGdCxv0y/F3xh+zZ2ltJpXqFm6xt1VwPDi5yKk+XKjFq
        fLAFsyB0VJDZFYvhvLvwwYYEU/GW3nffBpVrHIAL09AN59KeEAAACBAMATXeH6zICzwcAY
        kW5Yz3b/6DMiZogLiAaacdXvDirKTKw6ebCbUowZFj8CLduw2gnS980w80PQpP66uY68Yp
        ncBBzYIdDS5H3mdXA1CT6PUZXEcfdXrDKXYd+3xIndDdmGhdMjCWHSjNXvEleToKEIXKVd
        Y2Wcu0GrZP5El0zHAAAAC2ZpeC1yc2EyMDQ4AQIDBAUGBw==
        -----END OPENSSH PRIVATE KEY-----
        """, pubBlobB64: "AAAAB3NzaC1yc2EAAAADAQABAAABAQC3lQS9LrwckAROC0Rd8vfbw1fYl0UWO5k4zdLaiqDaPAEon4sK1zsu+cOVlnqEIw/oKlQqZSx6DlRhhNkQRtKlKO6PTRNARNHACCyKgIzSdoKFb03sF8xB1qgUKKculOxlZsHXu5wfLqcERHpggPGWeSJ/5SrlrYIHC68NWYxYbmg51HZgrKt/Z2wQP61cUS2jaU2JhnLmyx6qypopr8Ym4W+SdzuTkwvUlM7oOSwVNNu372tvmeiIPfp/0ikXXZIROUxft/a8u/4GtOGUyWwGhmNNA9/Re8UCze/2DRyoenF1JyypTu2dnw8BPB497G4Oev+qj7c84bapmeuTcVnn"),

        Fixture(name: "rsa-4096", pem: """
        -----BEGIN OPENSSH PRIVATE KEY-----
        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
        -----END OPENSSH PRIVATE KEY-----
        """, pubBlobB64: "AAAAB3NzaC1yc2EAAAADAQABAAACAQDwnAIZaoxCFaPltiKGtAeOYqb/P2tv8lED/8bAPKJNwTgOqWY9bl9vIO+zwBj4/uDFSMteXGs7yElagUrYli7FRbGZ5++Ty3p7RhLjXN8BMX3l6vj8JzrczWH6o8LZnUFze8nVZ3Zd0UfTtIYXD02Iz5l71Y71ebQyl7svUb1Df3VNa771Q+9livadELtCMAyrLlLRyXzqPbz601krFKFyWQQUzowrtbTYTsGjtQICk/N96oAGVWy7nqfs22hgI8IzdHASxa0VXmZGCeAKHvYbsIay677D1uiZUy1/SBqFfLbHbF+EFHvc1FlL8jTHEjIJ4tm54zia4vbZu5lx/N2ZihZ0nfXbTGaDWGkANcpPbht0hAxOIL5n8BrQDtgiUspab/tTOey0wk6QMc0qteZc0MRGZtr3/bqR+li/CnLCd//rZOIS80kanj0kL7EODoKFD2mjJa5jG0CxtmqtDAs1SFayBl49wpYREckgtUVLNpA7CTci2hxUrjWRzgqTCy9+SgZunF/mfKNIFSLVAvnuNw1Hle8a8vSY123FLOHcH4sRLID6z0HT0n5cVZE3Xk2xclY227rrT0Nj5LTfd772ffekl2gbcsTK7abKvhuCzLCNvLERpzFIxYGOwpxIyHDVHTbXXnQQKRKmGumMP34g6xq2FOVP1sJ7VYCgiMzNPQ=="),
    ]

    @Test("every key type parses to the SAME public blob ssh-keygen emitted")
    func publicBlobRoundTrips() throws {
        for f in Self.fixtures {
            let key = try SSHPrivateKey(opensshPEM: Data(f.pem.utf8))
            let expected = try #require(Data(base64Encoded: f.pubBlobB64), "\(f.name) fixture blob")
            #expect(key.publicKeyBlob == expected, "\(f.name): public blob mismatch")
        }
    }

    @Test("every key type signs a challenge that verifies under its public key")
    func signaturesVerify() throws {
        let challenge = Data("the server's auth challenge — sign me".utf8)
        for f in Self.fixtures {
            let key = try SSHPrivateKey(opensshPEM: Data(f.pem.utf8))
            // RSA: exercise the modern rsa-sha2-256 path (what current servers ask).
            let flags: SSHPrivateKey.SignFlags = f.name.hasPrefix("rsa") ? .rsaSha256 : []
            let sig = try key.sign(challenge, flags: flags)
            #expect(try SSHVerify.verify(pubBlob: key.publicKeyBlob, sigBlob: sig, data: challenge),
                    "\(f.name): signature did not verify")
            // A tampered message must NOT verify.
            #expect(try !SSHVerify.verify(pubBlob: key.publicKeyBlob, sigBlob: sig,
                                          data: challenge + Data([0x00])),
                    "\(f.name): signature verified against the wrong message")
        }
    }

    @Test("RSA honors the sha2-512 flag")
    func rsaSha512() throws {
        let key = try SSHPrivateKey(opensshPEM: Data(Self.fixtures.first { $0.name == "rsa-2048" }!.pem.utf8))
        let data = Data("rsa 512".utf8)
        let sig = try key.sign(data, flags: .rsaSha512)
        var r = SSHWire.Reader(sig)
        #expect(try r.stringUTF8() == "rsa-sha2-512")
        #expect(try SSHVerify.verify(pubBlob: key.publicKeyBlob, sigBlob: sig, data: data))
    }
}

/// A minimal SSH signature verifier — the server's side — so the tests confirm
/// our signatures are real, not just well-shaped. Test-only.
enum SSHVerify {
    static func verify(pubBlob: Data, sigBlob: Data, data: Data) throws -> Bool {
        var pk = SSHWire.Reader(pubBlob)
        let type = try pk.stringUTF8()
        var sr = SSHWire.Reader(sigBlob)
        _ = try sr.stringUTF8()                 // signature algorithm name
        let sig = try sr.string()

        switch type {
        case "ssh-ed25519":
            let pub = try pk.string()
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: pub)
            return key.isValidSignature(sig, for: data)

        case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
            _ = try pk.stringUTF8()             // curve
            let q = try pk.string()             // 0x04||X||Y
            var inner = SSHWire.Reader(sig)
            let r = try inner.mpint(), s = try inner.mpint()
            switch type {
            case "ecdsa-sha2-nistp256":
                let raw = pad(r, 32) + pad(s, 32)
                return try P256.Signing.PublicKey(x963Representation: q)
                    .isValidSignature(.init(rawRepresentation: raw), for: data)
            case "ecdsa-sha2-nistp384":
                let raw = pad(r, 48) + pad(s, 48)
                return try P384.Signing.PublicKey(x963Representation: q)
                    .isValidSignature(.init(rawRepresentation: raw), for: data)
            default:
                let raw = pad(r, 66) + pad(s, 66)
                return try P521.Signing.PublicKey(x963Representation: q)
                    .isValidSignature(.init(rawRepresentation: raw), for: data)
            }

        case "ssh-rsa":
            let e = try pk.mpint(), n = try pk.mpint()
            let der = derSeq([derInt(n), derInt(e)])
            let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA,
                                          kSecAttrKeyClass: kSecAttrKeyClassPublic]
            guard let pub = SecKeyCreateWithData(der as CFData, attrs as CFDictionary, nil) else { return false }
            var alg = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA1
            var a = SSHWire.Reader(sigBlob)
            switch try a.stringUTF8() {
            case "rsa-sha2-256": alg = .rsaSignatureMessagePKCS1v15SHA256
            case "rsa-sha2-512": alg = .rsaSignatureMessagePKCS1v15SHA512
            default: break
            }
            return SecKeyVerifySignature(pub, alg, data as CFData, sig as CFData, nil)

        default:
            return false
        }
    }

    private static func pad(_ d: Data, _ n: Int) -> Data {
        d.count >= n ? Data(d.suffix(n)) : Data(repeating: 0, count: n - d.count) + d
    }
    private static func derInt(_ mag: Data) -> Data {
        var m = mag
        while m.first == 0 && m.count > 1 { m.removeFirst() }
        if m.first.map({ $0 & 0x80 != 0 }) == true { m = Data([0]) + m }
        return derTLV(0x02, m)
    }
    private static func derSeq(_ parts: [Data]) -> Data { derTLV(0x30, parts.reduce(Data(), +)) }
    private static func derTLV(_ tag: UInt8, _ c: Data) -> Data {
        var len = Data()
        if c.count < 0x80 { len = Data([UInt8(c.count)]) }
        else { var v = c.count, b = [UInt8](); while v > 0 { b.insert(UInt8(v & 0xff), at: 0); v >>= 8 }; len = Data([0x80 | UInt8(b.count)] + b) }
        return Data([tag]) + len + c
    }
}
