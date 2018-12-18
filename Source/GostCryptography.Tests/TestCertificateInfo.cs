using System.Security.Cryptography.X509Certificates;

namespace GostCryptography.Tests
{
	public class TestCertificateInfo
	{
		public TestCertificateInfo(string name, X509Certificate2 certificate)
		{
			Name = name;
			Certificate = certificate;
		}


		public string Name { get; }

		public X509Certificate2 Certificate { get; }


		public override string ToString() => Name;
	}
}