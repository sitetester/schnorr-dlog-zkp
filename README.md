
A Rust implementation of Non-Interactive Schnorr Zero-Knowledge Discrete Logarithm Proof scheme with a Fiat-Shamir transformation.

Example program output:
```
Random secret: 0XEF5BEF789DE17759AC2293382D4D2D2DBB5D220F98BF99DF15D9FA61BCC7D778
Proof computation time: 1 ms
Verify computation time: 2 ms
✅ DLOG proof is correct
Printing proof...
-----Original-----
DLogProof { 
    t: ProjectivePoint { 
       x: FieldElement(FieldElementImpl { value: FieldElement5x52([965291443106997, 689422449863536, 1200405401125018, 3426219405815811, 215476664839722]), magnitude: 1, normalized: false }), 
       y: FieldElement(FieldElementImpl { value: FieldElement5x52([3900385919903053, 3633786440154162, 1783714629815838, 142161642848261, 169337120640621]), magnitude: 1, normalized: false }), 
       z: FieldElement(FieldElementImpl { value: FieldElement5x52([614627455921089, 4435624265092572, 2614043675640399, 2970682172781358, 195508401584888]), magnitude: 1, normalized: false }) 
    }, 
    s: Scalar(Uint(0x3D237241B7FEEA9ECDFCF315B529A5424A1FE6327C0BAD821F52371F804D8E33))
}
-----Affine-----
t: AffinePoint { 
    x: FieldElement(FieldElementImpl { value: FieldElement5x52([3498511524313427, 726385997402889, 1651688364219240, 4304763427786895, 56043366878661]), magnitude: 1, normalized: true }), 
    y: FieldElement(FieldElementImpl { value: FieldElement5x52([2966093787688926, 185048830672687, 3091769914310690, 4444249253916888, 172868112874250]), magnitude: 1, normalized: true }), 
    infinity: 0 
}
-----HEX-----
t.x: 0x32f89cf98dc5f4b28d6f4908f5de33aa3a9b68294a4eb585309c6de0b0a63953
t.y: 0x9d38fe75fb0afca056a12b0d8afbf2c77840220a84d09d17f2fa89a58695efde
s: 0x3d237241b7feea9ecdfcf315b529a5424a1fe6327c0bad821f52371f804d8e33
-----JSON-----
Compressed JSON (standard): {"t":"0232f89cf98dc5f4b28d6f4908f5de33aa3a9b68294a4eb585309c6de0b0a63953","s":"3d237241b7feea9ecdfcf315b529a5424a1fe6327c0bad821f52371f804d8e33"}
Uncompressed JSON (with both coordinates):
serde_json::to_string: {"t":{"x":"0x32f89cf98dc5f4b28d6f4908f5de33aa3a9b68294a4eb585309c6de0b0a63953","y":"0x9d38fe75fb0afca056a12b0d8afbf2c77840220a84d09d17f2fa89a58695efde"},"s":"0x3d237241b7feea9ecdfcf315b529a5424a1fe6327c0bad821f52371f804d8e33"}
serde_json::to_string_pretty: {
  "t": {
    "x": "0x32f89cf98dc5f4b28d6f4908f5de33aa3a9b68294a4eb585309c6de0b0a63953",
    "y": "0x9d38fe75fb0afca056a12b0d8afbf2c77840220a84d09d17f2fa89a58695efde"
  },
  "s": "0x3d237241b7feea9ecdfcf315b529a5424a1fe6327c0bad821f52371f804d8e33"
}
Parsed proof from JSON: 
DLogProof { t: ProjectivePoint { 
        x: FieldElement(FieldElementImpl { value: FieldElement5x52([3498511524313427, 726385997402889, 1651688364219240, 4304763427786895, 56043366878661]), magnitude: 1, normalized: true }), 
        y: FieldElement(FieldElementImpl { value: FieldElement5x52([2966093787688926, 185048830672687, 3091769914310690, 4444249253916888, 172868112874250]), magnitude: 1, normalized: true }), 
        z: FieldElement(FieldElementImpl { value: FieldElement5x52([1, 0, 0, 0, 0]), magnitude: 1, normalized: true }) 
    }, 
    s: Scalar(Uint(0x3D237241B7FEEA9ECDFCF315B529A5424A1FE6327C0BAD821F52371F804D8E33)) 
}
✅ DLog proof recovered successfully!
```
The last recovered proof look differently from `-----Original-----`, but these proofs actually do match mathematically, 
They look different because they represent the same point in different forms / internal states.

In `original`, we have  
x: [...965291443106997, ...],  
y: [...3900385919903053, ...],  
z: [...614627455921089, ...],   // z != 1  
normalized: false               // Not normalized

While the one recovered from JSON  
x: [...3498511524313427, ...],  // x/z  
y: [...2966093787688926, ...],  // y/z  
z: [1, 0, 0, 0, 0],             // z = 1  
normalized: true                // Normalized

Also the `s` values are identical:
```
s: 0x3D237241B7FEEA9ECDFCF315B529A5424A1FE6327C0BAD821F52371F804D8E33
```
