import Foundation

/// Minimal unsigned integer used to derive RSA CRT exponents
/// (dp = d mod (p - 1), dq = d mod (q - 1)) when importing an OpenSSH key. This
/// runs once when the key is loaded. The Security framework computes signatures.
///
/// Representation: base-2³² limbs, least-significant first, no trailing zero limbs.
struct BigUIntLite: Equatable {
    private(set) var limbs: [UInt32]   // little-endian; [] == 0

    init(limbs: [UInt32] = []) {
        self.limbs = limbs
        normalize()
    }

    /// Big-endian byte magnitude (as SSH mpints and DER integers store it).
    init(bigEndian bytes: Data) {
        var out: [UInt32] = []
        var acc: UInt32 = 0
        var shift: UInt32 = 0
        for b in bytes.reversed() {
            acc |= UInt32(b) << shift
            shift += 8
            if shift == 32 { out.append(acc); acc = 0; shift = 0 }
        }
        if shift > 0 { out.append(acc) }
        self.init(limbs: out)
    }

    private mutating func normalize() {
        while limbs.last == 0 { limbs.removeLast() }
    }

    var isZero: Bool { limbs.isEmpty }

    /// Minimal big-endian bytes (empty for zero).
    func bigEndianBytes() -> Data {
        var out = [UInt8]()
        for limb in limbs.reversed() {
            out.append(UInt8((limb >> 24) & 0xff))
            out.append(UInt8((limb >> 16) & 0xff))
            out.append(UInt8((limb >> 8) & 0xff))
            out.append(UInt8(limb & 0xff))
        }
        guard let firstNonzero = out.firstIndex(where: { $0 != 0 }) else { return Data() }
        return Data(out[firstNonzero...])
    }

    /// This value minus one, or zero when the value is zero or one.
    func minusOneOrZero() -> BigUIntLite {
        if isZero { return BigUIntLite(limbs: []) }
        var r = limbs
        var i = 0
        while true {
            if r[i] != 0 { r[i] -= 1; break }
            r[i] = 0xffff_ffff
            i += 1
        }
        return BigUIntLite(limbs: r)   // One normalizes to zero.
    }

    private static func compare(_ a: [UInt32], _ b: [UInt32]) -> Int {
        if a.count != b.count { return a.count < b.count ? -1 : 1 }
        var i = a.count - 1
        while i >= 0 {
            if a[i] != b[i] { return a[i] < b[i] ? -1 : 1 }
            i -= 1
        }
        return 0
    }

    /// This value modulo `modulus` using bit-by-bit long division. Returns this
    /// value for a zero modulus.
    func mod(_ modulus: BigUIntLite) -> BigUIntLite {
        if modulus.isZero { return self }
        if BigUIntLite.compare(limbs, modulus.limbs) < 0 { return self }
        var rem = BigUIntLite(limbs: [])
        let totalBits = limbs.count * 32
        var i = totalBits - 1
        while i >= 0 {
            rem = rem.shiftedLeftOne()
            if bit(at: i) { rem.setBit0() }
            if BigUIntLite.compare(rem.limbs, modulus.limbs) >= 0 {
                rem = rem.subtracting(modulus)
            }
            i -= 1
        }
        return rem
    }

    private func bit(at index: Int) -> Bool {
        let limb = index / 32, off = index % 32
        guard limb < limbs.count else { return false }
        return (limbs[limb] >> UInt32(off)) & 1 == 1
    }

    private mutating func setBit0() {
        if limbs.isEmpty { limbs = [1] } else { limbs[0] |= 1 }
    }

    private func shiftedLeftOne() -> BigUIntLite {
        var out = [UInt32]()
        var carry: UInt32 = 0
        for limb in limbs {
            out.append((limb << 1) | carry)
            carry = (limb >> 31) & 1
        }
        if carry != 0 { out.append(carry) }
        return BigUIntLite(limbs: out)
    }

    /// self − other, self ≥ other.
    private func subtracting(_ other: BigUIntLite) -> BigUIntLite {
        var out = [UInt32]()
        var borrow: UInt64 = 0
        for i in 0..<limbs.count {
            let a = UInt64(limbs[i])
            let b = i < other.limbs.count ? UInt64(other.limbs[i]) : 0
            let diff = a &- b &- borrow
            if a < b + borrow { borrow = 1 } else { borrow = 0 }
            out.append(UInt32(diff & 0xffff_ffff))
        }
        return BigUIntLite(limbs: out)
    }
}
