using System;
using System.Security.Cryptography.X509Certificates;

namespace GostCryptography.Tests
{
	public class TestCertificateInfo
	{
		private readonly string _name;
		private readonly Lazy<X509Certificate2> _certificate;


		public TestCertificateInfo(string name, Func<X509Certificate2> supplier)
		{
			_name = name;
			_certificate = new Lazy<X509Certificate2>(supplier);
		}


		public X509Certificate2 Certificate => _certificate.Value;


		public override string ToString() => _name;
	}
}