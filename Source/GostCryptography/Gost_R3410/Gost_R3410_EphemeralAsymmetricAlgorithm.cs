using System;
using System.Security;
using System.Security.Cryptography;

using GostCryptography.Asn1.Gost.Gost_R3410;
using GostCryptography.Base;
using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Реализация алгоритма формирования общих ключей на основе алгоритма ГОСТ Р 34.10 и эфимерного ключа.
	/// </summary>
	public abstract class Gost_R3410_EphemeralAsymmetricAlgorithm<TKeyParams, TKeyAlgorithm> : Gost_R3410_AsymmetricAlgorithmBase<TKeyParams, TKeyAlgorithm>, ISafeHandleProvider<SafeProvHandleImpl>, ISafeHandleProvider<SafeKeyHandleImpl>
		where TKeyParams : Gost_R3410_KeyExchangeParams
		where TKeyAlgorithm : Gost_R3410_KeyExchangeAlgorithm
	{
		/// <inheritdoc />
		[SecuritySafeCritical]
		protected Gost_R3410_EphemeralAsymmetricAlgorithm(ProviderType providerType, int keySize) : base(providerType, keySize)
		{
			_providerHandle = CryptoApiHelper.GetProviderHandle(ProviderType).DangerousAddRef();
			_keyHandle = CryptoApiHelper.GenerateKey(_providerHandle, ExchangeAlgId, CspProviderFlags.NoFlags);
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerType">Тип криптографического провайдера.</param>
		/// <param name="keyParameters">Параметры ключа, используемого для создания общего секретного ключа.</param>
		/// <param name="keySize">Размер ключа в битах.</param>
		/// <exception cref="ArgumentNullException"></exception>
		/// <remarks>
		/// В параметре <paramref name="keyParameters"/> достаточно передать идентификатор OID параметров хэширования
		/// <see cref="Gost_R3410_KeyExchangeParams.DigestParamSet"/> и идентификатор OID параметров открытого ключа
		/// <see cref="Gost_R3410_KeyExchangeParams.PublicKeyParamSet"/>. Остальные параметры не используются.
		/// </remarks>
		[SecuritySafeCritical]
		protected Gost_R3410_EphemeralAsymmetricAlgorithm(ProviderType providerType, TKeyParams keyParameters, int keySize) : base(providerType, keySize)
		{
			if (keyParameters == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyParameters));
			}

			_providerHandle = CryptoApiHelper.GetProviderHandle(ProviderType).DangerousAddRef();
			_keyHandle = CryptoApiHelper.GenerateDhEphemeralKey(providerType, _providerHandle, ExchangeAlgId, keyParameters.DigestParamSet, keyParameters.PublicKeyParamSet);
		}


		[SecurityCritical]
		private readonly SafeProvHandleImpl _providerHandle;
		[SecurityCritical]
		private readonly SafeKeyHandleImpl _keyHandle;


		/// <inheritdoc />
		SafeProvHandleImpl ISafeHandleProvider<SafeProvHandleImpl>.SafeHandle
		{
			[SecurityCritical]
			get => _providerHandle;
		}

		/// <inheritdoc />
		SafeKeyHandleImpl ISafeHandleProvider<SafeKeyHandleImpl>.SafeHandle
		{
			[SecurityCritical]
			get => _keyHandle;
		}


		/// <inheritdoc />
		public override byte[] CreateSignature(byte[] hash)
		{
			throw ExceptionUtility.NotSupported(Resources.EphemKeyOperationNotSupported);
		}

		/// <inheritdoc />
		public override bool VerifySignature(byte[] hash, byte[] signature)
		{
			throw ExceptionUtility.NotSupported(Resources.EphemKeyOperationNotSupported);
		}


		/// <inheritdoc />
		[SecuritySafeCritical]
		public override TKeyAlgorithm CreateKeyExchange(TKeyParams keyParameters)
		{
			return CreateKeyExchangeAlgorithm(ProviderType, _providerHandle, _keyHandle, (TKeyParams)keyParameters.Clone());
		}


		/// <inheritdoc />
		[SecuritySafeCritical]
		public override TKeyParams ExportParameters(bool includePrivateKey)
		{
			if (includePrivateKey)
			{
				throw ExceptionUtility.NotSupported(Resources.EphemKeyOperationNotSupported);
			}

			return CryptoApiHelper.ExportPublicKey(_keyHandle, CreateKeyExchangeParams(), KeySizeValue);
		}

		/// <inheritdoc />
		public override void ImportParameters(TKeyParams keyParameters)
		{
			throw ExceptionUtility.NotSupported(Resources.EphemKeyOperationNotSupported);
		}


		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override void Dispose(bool disposing)
		{
			_keyHandle.TryDispose();
			_providerHandle.TryDispose();

			base.Dispose(disposing);
		}
	}
}