using System;
using System.Security.Cryptography;

using GostCryptography.Properties;

namespace GostCryptography.Base
{
	/// <summary>
	/// На базе заданного экземпляра <see cref="AsymmetricAlgorithm"/> пытается реализовать <see cref="GostAsymmetricAlgorithm"/>.
	/// Данный класс предназначен для интеграции со сторонними библиотеками и предназначен для внутреннего использования.
	/// </summary>
	sealed class GostExternalAsymmetricAlgorithm : GostAsymmetricAlgorithm
	{
		private readonly AsymmetricAlgorithm _algorithm;
		private readonly Func<byte[], byte[]> _createSignature;
		private readonly Func<byte[], byte[], bool> _verifySignature;


		public GostExternalAsymmetricAlgorithm(AsymmetricAlgorithm algorithm) : base(default(ProviderType), algorithm.KeySize)
		{
			var createSignatureMethod = algorithm.GetType().GetMethod(nameof(CreateSignature), new[] { typeof(byte[]) });
			var verifySignatureMethod = algorithm.GetType().GetMethod(nameof(VerifySignature), new[] { typeof(byte[]), typeof(byte[]) });

			if ((createSignatureMethod == null || createSignatureMethod.ReturnType != typeof(byte[]))
			    || (verifySignatureMethod == null || verifySignatureMethod.ReturnType != typeof(bool)))
			{
				throw ExceptionUtility.Argument(nameof(algorithm), Resources.ShouldSupportGost3410);
			}

			_algorithm = algorithm;
			_createSignature = hash => (byte[])createSignatureMethod.Invoke(algorithm, new object[] { hash });
			_verifySignature = (hash, signature) => (bool)verifySignatureMethod.Invoke(algorithm, new object[] { hash, signature });
		}


		public override string AlgorithmName => _algorithm.SignatureAlgorithm;

		public override string SignatureAlgorithm => _algorithm.SignatureAlgorithm;

		public override string KeyExchangeAlgorithm => _algorithm.KeyExchangeAlgorithm;


		public override string ToXmlString(bool includePrivateKey) => _algorithm.ToXmlString(includePrivateKey);

		public override void FromXmlString(string keyParametersXml) => _algorithm.FromXmlString(keyParametersXml);


		public override byte[] CreateSignature(byte[] hash) => _createSignature(hash);

		public override bool VerifySignature(byte[] hash, byte[] signature) => _verifySignature(hash, signature);


		public override GostHashAlgorithm CreateHashAlgorithm() => throw ExceptionUtility.NotSupported();

		public override GostKeyExchangeFormatter CreateKeyExchangeFormatter() => throw ExceptionUtility.NotSupported();

		public override GostKeyExchangeDeformatter CreateKeyExchangeDeformatter() => throw ExceptionUtility.NotSupported();
	}
}