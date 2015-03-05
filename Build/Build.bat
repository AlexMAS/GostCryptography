call "C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\vcvarsall.bat"

msbuild "..\GostCryptography.sln" /t:Clean /p:Configuration=Release
msbuild "..\GostCryptography.sln" /p:Configuration=Release

if exist "..\Assemblies\Package\" rmdir /s /q "..\Assemblies\Package\"
mkdir "..\Assemblies\Package"
mkdir "..\Assemblies\Package\lib"

copy "..\Assemblies\GostCryptography.dll" "..\Assemblies\Package\lib\GostCryptography.dll"
copy "..\Assemblies\GostCryptography.xml" "..\Assemblies\Package\lib\GostCryptography.xml"
copy "GostCryptography.nuspec" "..\Assemblies\Package\GostCryptography.nuspec"

set EnableNuGetPackageRestore=true
"..\Tools\NuGet\NuGet.exe" pack "..\Assemblies\Package\GostCryptography.nuspec" -OutputDirectory "..\Assemblies\Package"