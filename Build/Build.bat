msbuild "..\GostCryptography.net40.sln" /t:Clean /p:Configuration=Release
msbuild "..\GostCryptography.net40.sln" /p:Configuration=Release /p:FrameworkPathOverride="%PROGRAMFILES(X86)%\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.5.2"
msbuild "..\GostCryptography.net45.sln" /t:Clean /p:Configuration=Release
msbuild "..\GostCryptography.net45.sln" /p:Configuration=Release

if exist "..\Assemblies\Package\" rmdir /s /q "..\Assemblies\Package\"
mkdir "..\Assemblies\Package"
mkdir "..\Assemblies\Package\lib"
mkdir "..\Assemblies\Package\lib\net40"
mkdir "..\Assemblies\Package"
mkdir "..\Assemblies\Package\lib"
mkdir "..\Assemblies\Package\lib\net452"

copy "GostCryptography.nuspec" "..\Assemblies\Package\GostCryptography.nuspec"
copy "..\Assemblies\net40\GostCryptography.dll" "..\Assemblies\Package\lib\net40\GostCryptography.dll"
copy "..\Assemblies\net40\GostCryptography.xml" "..\Assemblies\Package\lib\net40\GostCryptography.xml"
copy "..\Assemblies\net45\GostCryptography.dll" "..\Assemblies\Package\lib\net452\GostCryptography.dll"
copy "..\Assemblies\net45\GostCryptography.xml" "..\Assemblies\Package\lib\net452\GostCryptography.xml"

set EnableNuGetPackageRestore=true
"..\Tools\NuGet\NuGet.exe" pack "..\Assemblies\Package\GostCryptography.nuspec" -OutputDirectory "..\Assemblies\Package"
