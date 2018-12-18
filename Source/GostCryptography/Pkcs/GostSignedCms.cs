using System.Security;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

using GostCryptography.Config;

namespace GostCryptography.Pkcs
{
	/// <summary>
	/// Реализует методы для работы с сообщениями CMS (Cryptographic Message Syntax) / PKCS #7 (Public-Key Cryptography Standard #7).
	/// </summary>
	/// <remarks>
	/// CMS (Cryptographic Message Syntax) или PKCS #7 (Public-Key Cryptography Standard #7) - это стандарт, поддерживаемый RSA Laboratories,
	/// который описываемый синтаксис криптографических сообщений. Синтаксис CMS описывает способы формирования криптографических сообщений, 
	/// в результате чего сообщение становится полностью самодостаточным для его открытия и выполнения всех необходимых операций. С этой целью 
	/// в CMS-сообщении размещается информация об исходном сообщении, алгоритмах хэширования и подписи, параметрах криптоалгоритмов, времени
	/// подписи, сертификат ключа электронной подписи, цепочка сертификации и т.д. Большинство из перечисленных атрибутов CMS-сообщения являются
	/// опциональными, но их обязательность может определяться прикладной системой. Отдельно следует отметить, что CMS/PKCS#7 позволяет ставить 
	/// несколько подписей под одним документом, сохраняя всю необходимую информацию в сообщении. 
	/// </remarks>
	public sealed class GostSignedCms
	{
		static GostSignedCms()
		{
			GostCryptoConfig.Initialize();
		}

		/// <inheritdoc cref="SignedCms()"/>
		public GostSignedCms()
		{
			_signedCms = new SignedCms();
			_signerIdentifierType = InitSubjectIdentifierType(SubjectIdentifierType.IssuerAndSerialNumber);
		}

		/// <inheritdoc cref="SignedCms(SubjectIdentifierType)"/>
		public GostSignedCms(SubjectIdentifierType signerIdentifierType)
		{
			_signedCms = new SignedCms(signerIdentifierType);
			_signerIdentifierType = InitSubjectIdentifierType(signerIdentifierType);
		}

		/// <inheritdoc cref="SignedCms(System.Security.Cryptography.Pkcs.ContentInfo)"/>
		public GostSignedCms(ContentInfo contentInfo)
		{
			_signedCms = new SignedCms(contentInfo);
			_signerIdentifierType = InitSubjectIdentifierType(SubjectIdentifierType.IssuerAndSerialNumber);
		}

		/// <inheritdoc cref="SignedCms(SubjectIdentifierType,System.Security.Cryptography.Pkcs.ContentInfo)"/>
		public GostSignedCms(SubjectIdentifierType signerIdentifierType, ContentInfo contentInfo)
		{
			_signedCms = new SignedCms(signerIdentifierType, contentInfo);
			_signerIdentifierType = InitSubjectIdentifierType(signerIdentifierType);
		}

		/// <inheritdoc cref="SignedCms(System.Security.Cryptography.Pkcs.ContentInfo,bool)"/>
		public GostSignedCms(ContentInfo contentInfo, bool detached)
		{
			_signedCms = new SignedCms(contentInfo, detached);
			_signerIdentifierType = InitSubjectIdentifierType(SubjectIdentifierType.IssuerAndSerialNumber);
		}

		/// <inheritdoc cref="SignedCms(SubjectIdentifierType,System.Security.Cryptography.Pkcs.ContentInfo,bool)"/>
		public GostSignedCms(SubjectIdentifierType signerIdentifierType, ContentInfo contentInfo, bool detached)
		{
			_signedCms = new SignedCms(signerIdentifierType, contentInfo, detached);
			_signerIdentifierType = InitSubjectIdentifierType(signerIdentifierType);
		}


		private readonly SignedCms _signedCms;
		private readonly SubjectIdentifierType _signerIdentifierType;


		/// <inheritdoc cref="SignedCms.Version"/>
		public int Version => _signedCms.Version;

		/// <inheritdoc cref="SignedCms.ContentInfo"/>
		public ContentInfo ContentInfo => _signedCms.ContentInfo;

		/// <inheritdoc cref="SignedCms.Detached"/>
		public bool Detached => _signedCms.Detached;

		/// <inheritdoc cref="SignedCms.Certificates"/>
		public X509Certificate2Collection Certificates => _signedCms.Certificates;

		/// <inheritdoc cref="SignedCms.SignerInfos"/>
		public SignerInfoCollection SignerInfos => _signedCms.SignerInfos;


		/// <inheritdoc cref="SignedCms.Encode"/>
		public byte[] Encode()
		{
			return _signedCms.Encode();
		}

		/// <inheritdoc cref="SignedCms.Decode"/>
		public void Decode(byte[] encodedMessage)
		{
			_signedCms.Decode(encodedMessage);
		}


		/// <inheritdoc cref="SignedCms.ComputeSignature()"/>
		public void ComputeSignature()
		{
			ComputeSignature(new CmsSigner(_signerIdentifierType), true);
		}

		/// <inheritdoc cref="SignedCms.ComputeSignature(CmsSigner)"/>
		public void ComputeSignature(CmsSigner signer)
		{
			ComputeSignature(signer, true);
		}

		/// <inheritdoc cref="SignedCms.ComputeSignature(CmsSigner,bool)"/>
		public void ComputeSignature(CmsSigner signer, bool silent)
		{
			signer = InitCmsSigner(signer);

			_signedCms.ComputeSignature(signer, silent);
		}


		/// <inheritdoc cref="SignedCms.RemoveSignature(int)"/>
		public void RemoveSignature(int index)
		{
			_signedCms.RemoveSignature(index);
		}

		/// <inheritdoc cref="SignedCms.RemoveSignature(SignerInfo)"/>
		public void RemoveSignature(SignerInfo signerInfo)
		{
			_signedCms.RemoveSignature(signerInfo);
		}


		/// <inheritdoc cref="SignedCms.CheckSignature(bool)"/>
		public void CheckSignature(bool verifySignatureOnly)
		{
			_signedCms.CheckSignature(verifySignatureOnly);
		}

		/// <inheritdoc cref="SignedCms.CheckSignature(X509Certificate2Collection,bool)"/>
		public void CheckSignature(X509Certificate2Collection extraStore, bool verifySignatureOnly)
		{
			_signedCms.CheckSignature(extraStore, verifySignatureOnly);
		}


		/// <inheritdoc cref="SignedCms.CheckHash()"/>
		public void CheckHash()
		{
			_signedCms.CheckHash();
		}


		private static SubjectIdentifierType InitSubjectIdentifierType(SubjectIdentifierType signerIdentifierType)
		{
			if (signerIdentifierType != SubjectIdentifierType.SubjectKeyIdentifier
				&& signerIdentifierType != SubjectIdentifierType.IssuerAndSerialNumber
				&& signerIdentifierType != SubjectIdentifierType.NoSignature)
			{
				return SubjectIdentifierType.IssuerAndSerialNumber;
			}

			return signerIdentifierType;
		}

		[SecuritySafeCritical]
		private static CmsSigner InitCmsSigner(CmsSigner cmsSigner)
		{
			var certificate = cmsSigner.Certificate;

			var hashAlgorithm = certificate?.GetHashAlgorithm();

			if (hashAlgorithm != null)
			{
				cmsSigner.DigestAlgorithm = hashAlgorithm;
			}

			return cmsSigner;
		}
	}
}