Authenticode Examiner
=====================

Authenticode Examiner is a Windows-only library for inspecting, verifying, and examining
any Authenticode signed file such a DLL, EXE, MSI, CAB, etc.

The library is a wrapper around native Windows APIs that provide this functionality. This
is an intentional design decision to avoid having to implement security-critical code, and
to ensure forward compatibility as Windows gains new functionality for new file types.

Authenticode Examiner has three components for its use.

## Verifying Signatures

Validating the integrity of an Authenticode signed file is simple enough using:

```csharp
var inspector = new FileInspector(path_to_file);
var validationResult = inspector.Validate();
```

The result of `Validate` will be `Valid` if the signature. All other values of the
enumeration indicate some kind of failure. The enumeration is also not exhaustive,
that is it may contain unnamed values indicating failure. Therefore, testing for
`Valid` specificially must be done to check for validity. Checking only the failure
cases and assuming it is valid if none of the error cases match is incorrect.

### Correct

```csharp
var inspector = new FileInspector(path);
var result = inspector.Validate();
if (result == SignatureCheckResult.Valid) {
    Console.WriteLine("VALID!");
}
else if (result == SignatureCheckResult.BadDigest) {
    Console.WriteLine("BAD SIGNATURE!");
}
//More cases if desired
else {
    Console.WriteLine("IT'S BAD FOR SOME REASON!");
}
```

### Incorrect

```csharp
#error This is example code that is incorrect and should not be used.
var inspector = new FileInspector(path);
var result = inspector.Validate();
if (result == SignatureCheckResult.BadDigest) {
    Console.WriteLine("BAD SIGNATURE!");
}
else { //Incorrect!
    Console.WriteLine("VALID!");
}
```

## Inspecting Signatures

There are two means of inspecting the signatures themselves. There is
a high level approach for getting basic signature details in a "flattened"
structure. This makes it easy to enumerate basic signature information without
too much detail about how the signature is actually formed.


```csharp
var inspector = new FileInspector(path);
var signatures = inspector.GetSignatures();
```

`signatures` is an enumerable of `AuthenticodeSignature`, which contains basic
information about a signature, and related timestamp signatures, and the
certificate of the signature. Note that this intentionally does not expose an
API for determining if an individual signature is valid or not; Authenticode
validity of a file must consider things other than individual signatures. For
determining validity, use the `Validate` on `FileInspector`.

Lower-level signature details can be determined using `SignatureTreeInspector`.
This type can be used to determine how signatures relate to one another and
getting specific signature types. For example, to get only RFC3161 timestamp
signatures:

```csharp
var signatures = SignatureTreeInspector.Extract(path);
var rfc3161 = signatures.VisitAll(SignatureKind.Rfc3161Timestamp, true);
```

Generally, the higher-level API in `FileInspector` is preferable.

A complete example is available in the `sample` sub directory of the repository.