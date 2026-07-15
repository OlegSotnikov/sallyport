import Foundation

/// Reassembles newline-delimited frames from arbitrary byte chunks.
public struct LineFramer: Sendable {
    private var buffer: Data = Data()
    /// Bytes in the trailing partial frame already searched for a newline.
    /// Avoids rescanning the existing partial frame on each read.
    private var scannedByteCount = 0
    private let maxLineBytes: Int

    /// - Parameter maxLineBytes: Maximum partial frame size. Defaults to 8 MiB.
    public init(maxLineBytes: Int = 8 * 1024 * 1024) {
        self.maxLineBytes = maxLineBytes
    }

    public enum FramerError: Error, Equatable {
        case lineTooLong(Int)
    }

    /// Append a chunk and return any complete lines (without the trailing `\n`).
    /// Empty lines are skipped. Throws if the pending line grows past the cap.
    public mutating func push(_ chunk: Data) throws -> [Data] {
        buffer.append(chunk)
        var lines: [Data] = []
        var cursor = min(scannedByteCount, buffer.count)
        var lineStart = 0
        var consumed = 0

        // Scan only bytes that arrived since the last push. Accumulate the
        // consumed prefix and remove it once; repeated front-removal is also
        // quadratic for a chunk containing many short frames.
        while cursor < buffer.count {
            let searchStart = buffer.index(buffer.startIndex, offsetBy: cursor)
            guard let nl = buffer[searchStart...].firstIndex(of: 0x0A) else { break }
            let newlineOffset = buffer.distance(from: buffer.startIndex, to: nl)
            let lineBytes = newlineOffset - lineStart
            guard lineBytes <= maxLineBytes else {
                throw FramerError.lineTooLong(lineBytes)
            }
            if lineBytes > 0 {
                let start = buffer.index(buffer.startIndex, offsetBy: lineStart)
                lines.append(Data(buffer[start..<nl]))
            }
            consumed = newlineOffset + 1
            lineStart = consumed
            cursor = consumed
        }

        let pending = buffer.count - lineStart
        guard pending <= maxLineBytes else {
            throw FramerError.lineTooLong(pending)
        }
        if consumed > 0 {
            let end = buffer.index(buffer.startIndex, offsetBy: consumed)
            buffer.removeSubrange(buffer.startIndex..<end)
        }
        scannedByteCount = buffer.count
        return lines
    }

    /// Bytes buffered but not yet terminated by a newline.
    public var pendingByteCount: Int { buffer.count }
}
