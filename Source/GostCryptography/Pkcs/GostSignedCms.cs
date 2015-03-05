using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

using GostCryptography.Cryptography;

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

		public GostSignedCms()
		{
			_signedCms = new SignedCms();
			_signerIdentifierType = InitSubjectIdentifierType(SubjectIdentifierType.IssuerAndSerialNumber);
		}

		public GostSignedCms(SubjectIdentifierType signerIdentifierType)
		{
			_signedCms = new SignedCms(signerIdentifierType);
			_signerIdentifierType = InitSubjectIdentifierType(signerIdentifierType);
		}

		public GostSignedCms(ContentInfo contentInfo)
		{
			_signedCms = new SignedCms(contentInfo);
			_signerIdentifierType = InitSubjectIdentifierType(SubjectIdentifierType.IssuerAndSerialNumber);
		}

		public GostSignedCms(SubjectIdentifierType signerIdentifierType, ContentInfo contentInfo)
		{
			_signedCms = new SignedCms(signerIdentifierType, contentInfo);
			_signerIdentifierType = InitSubjectIdentifierType(signerIdentifierType);
		}

		public GostSignedCms(ContentInfo contentInfo, bool detached)
		{
			_signedCms = new SignedCms(contentInfo, detached);
			_signerIdentifierType = InitSubjectIdentifierType(SubjectIdentifierType.IssuerAndSerialNumber);
		}

		public GostSignedCms(SubjectIdentifierType signerIdentifierType, ContentInfo contentInfo, bool detached)
		{
			_signedCms = new SignedCms(signerIdentifierType, contentInfo, detached);
			_signerIdentifierType = InitSubjectIdentifierType(signerIdentifierType);
		}


		private readonly SignedCms _signedCms;
		private readonly SubjectIdentifierType _signerIdentifierType;


		public int Version
		{
			get { return _signedCms.Version; }
		}

		public ContentInfo ContentInfo
		{
			get { return _signedCms.ContentInfo; }
		}

		public bool Detached
		{
			get { return _signedCms.Detached; }
		}

		public X509Certificate2Collection Certificates
		{
			get { return _signedCms.Certificates; }
		}

		public SignerInfoCollection SignerInfos
		{
			get { return _signedCms.SignerInfos; }
		}

		public byte[] Encode()
		{
			return _signedCms.Encode();
		}

		public void Decode(byte[] encodedMessage)
		{
			_signedCms.Decode(encodedMessage);
		}

		public void ComputeSignature()
		{
			ComputeSignature(new CmsSigner(_signerIdentifierType), true);
		}

		public void ComputeSignature(CmsSigner signer)
		{
			ComputeSignature(signer, true);
		}

		public void ComputeSignature(CmsSigner signer, bool silent)
		{
			signer = InitCmsSigner(signer);

			_signedCms.ComputeSignature(signer, silent);
		}

		public void RemoveSignature(int index)
		{
			_signedCms.RemoveSignature(index);
		}

		public void RemoveSignature(SignerInfo signerInfo)
		{
			_signedCms.RemoveSignature(signerInfo);
		}

		public void CheckSignature(bool verifySignatureOnly)
		{
			_signedCms.CheckSignature(verifySignatureOnly);
		}

		public void CheckSignature(X509Certificate2Collection extraStore, bool verifySignatureOnly)
		{
			_signedCms.CheckSignature(extraStore, verifySignatureOnly);
		}

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

		private static CmsSigner InitCmsSigner(CmsSigner cmsSigner)
		{
			var certificate = cmsSigner.Certificate;

			if (certificate != null)
			{
				var keyAlgorithm = certificate.GetKeyAlgorithm();

				if (string.Equals(keyAlgorithm, GostCryptoConfig.DefaultSignOid, StringComparison.OrdinalIgnoreCase))
				{
					cmsSigner.DigestAlgorithm = new Oid(GostCryptoConfig.DefaultHashOid);
				}
			}

			return cmsSigner;
		}
	}
}