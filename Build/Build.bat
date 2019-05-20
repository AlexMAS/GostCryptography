msbuild "..\GostCryptography.sln" /t:Clean /p:Configuration=Release
msbuild "..\GostCryptography.sln" /p:Configuration=Release

if exist "..\Assemblies\Package\" rmdir /s /q "..\Assemblies\Package\"
mkdir "..\Assemblies\Package"
mkdir "..\Assemblies\Package\lib"
mkdir "..\Assemblies\Package\lib\net40"
mkdir "..\Assemblies\Package\src"
mkdir "..\Assemblies\Package\src\Source"
mkdir "..\Assemblies\Package\src\Source\GostCryptography"

copy "GostCryptography.nuspec" "..\Assemblies\Package\GostCryptography.nuspec"
copy "..\Assemblies\GostCryptography.dll" "..\Assemblies\Package\lib\net40\GostCryptography.dll"
copy "..\Assemblies\GostCryptography.pdb" "..\Assemblies\Package\lib\net40\GostCryptography.pdb"
copy "..\Assemblies\GostCryptography.xml" "..\Assemblies\Package\lib\net40\GostCryptography.xml"
xcopy "..\Source" "..\Assemblies\Package\src\Source" /E /Q /EXCLUDE:BuildExclude.txt

set EnableNuGetPackageRestore=true
"..\Tools\NuGet\NuGet.exe" pack "..\Assemblies\Package\GostCryptography.nuspec" -OutputDirectory "..\Assemblies\Package" -symbols