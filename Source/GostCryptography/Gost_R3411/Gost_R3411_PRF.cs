using System;
using System.Security;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;
using GostCryptography.Native;

namespace GostCryptography.Gost_R3411
{
	/// <summary>
	/// Базовый класс для всех реализаций генераТора псевдослучайной последовательности (Pseudorandom Function, PRF) на базе алгоритма хэширования ГОСТ Р 34.11.
	/// </summary>
	public abstract class Gost_R3411_PRF : GostPRF
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="key">Симметричный ключ ГОСТ 28147 для вычисления HMAC на основе алгоритма ГОСТ Р 34.11.</param>
		/// <param name="label">Метка для порождения ключей (аргумент label функции PRF).</param>
		/// <param name="seed">Начальное число для порождения ключей (аргумент seed функции PRF).</param>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
		protected Gost_R3411_PRF(Gost_28147_89_SymmetricAlgorithmBase key, byte[] label, byte[] seed)
			: this(key.ProviderType, Gost_28147_89_SymmetricAlgorithm.CreateFromKey(key), label, seed)
		{
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerType">Тип криптографического провайдера.</param>
		/// <param name="key">Симметричный ключ ГОСТ 28147 для вычисления HMAC на основе алгоритма ГОСТ Р 34.11.</param>
		/// <param name="label">Метка для порождения ключей (аргумент label функции PRF).</param>
		/// <param name="seed">Начальное число для порождения ключей (аргумент seed функции PRF).</param>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
		protected Gost_R3411_PRF(ProviderTypes providerType, byte[] key, byte[] label, byte[] seed)
			: this(providerType, Gost_28147_89_SymmetricAlgorithm.CreateFromSessionKey(providerType, key), label, seed)
		{
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerType">Тип криптографического провайдера.</param>
		/// <param name="key">Симметричный ключ ГОСТ 28147 для вычисления HMAC на основе алгоритма ГОСТ Р 34.11.</param>
		/// <param name="label">Метка для порождения ключей (аргумент label функции PRF).</param>
		/// <param name="seed">Начальное число для порождения ключей (аргумент seed функции PRF).</param>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
		private Gost_R3411_PRF(ProviderTypes providerType, Gost_28147_89_SymmetricAlgorithm key, byte[] label, byte[] seed) : base(providerType)
		{
			if (label == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(label));
			}

			if (seed == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(seed));
			}

			_key = key;

			var labelAndSeed = new byte[label.Length + seed.Length];
			label.CopyTo(labelAndSeed, 0);
			seed.CopyTo(labelAndSeed, label.Length);

			_labelAndSeed = labelAndSeed;
			_buffer = new byte[labelAndSeed.Length + 32];

			_value = labelAndSeed;
			_keyIndex = 0;

			_hashHmacHandle = SafeHashHandleImpl.InvalidHandle;
		}


		private readonly Gost_28147_89_SymmetricAlgorithm _key;
		private readonly byte[] _labelAndSeed;
		private readonly byte[] _buffer;
		private byte[] _value;
		private int _keyIndex;

		[SecurityCritical]
		private SafeHashHandleImpl _hashHmacHandle;


		/// <summary>
		/// Возаращает очередной набор псевдослучайной последовательности.
		/// </summary>
		/// <remarks>
		/// Размер последовательности зависит от алгоритма хэширования.
		/// </remarks>
		[SecurityCritical]
		public byte[] DeriveBytes()
		{
			GenerateNextBytes();

			return CryptoApiHelper.EndHashData(_hashHmacHandle);
		}

		/// <summary>
		/// Возвращает псевдослучайный симметричный ключ ГОСТ 28147.
		/// </summary>
		[SecuritySafeCritical]
		public Gost_28147_89_SymmetricAlgorithmBase DeriveKey()
		{
			GenerateNextBytes();

			var providerHandle = CryptoApiHelper.GetProviderHandle(ProviderType);
			var symKeyHandle = CryptoApiHelper.DeriveSymKey(providerHandle, _hashHmacHandle);

			return new Gost_28147_89_SymmetricAlgorithm(ProviderType, providerHandle, symKeyHandle);
		}

		/// <summary>
		/// Возвращает псевдослучайный симметричный ключ ГОСТ 28147.
		/// </summary>
		/// <param name="position">Позиция ключа в псевдослучайной последовательности.</param>
		/// <exception cref="ArgumentOutOfRangeException">Если позиция ключа <paramref name="position"/> не кратна 256 или ключ с требуемой позицией уже был создан.</exception>
		[SecurityCritical]
		public Gost_28147_89_SymmetricAlgorithmBase DeriveKey(int position)
		{
			if ((position % 256) != 0)
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(position));
			}

			var keyIndex = position / 256;

			if (keyIndex < _keyIndex)
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(position));
			}

			while (keyIndex > _keyIndex)
			{
				DeriveKey().Clear();
			}

			return DeriveKey();
		}


		[SecurityCritical]
		private void GenerateNextBytes()
		{
			InitializeHmac();

			_value = ComputeHash(_value);
			_value.CopyTo(_buffer, 0);
			_labelAndSeed.CopyTo(_buffer, _value.Length);

			InitializeHmac();
			CryptoApiHelper.HashData(_hashHmacHandle, _buffer, 0, _buffer.Length);

			_keyIndex++;
		}

		[SecurityCritical]
		private void InitializeHmac()
		{
			// TODO:
			var hashHmacHandle = CryptoApiHelper.CreateHashHMAC_94(ProviderType, CryptoApiHelper.GetProviderHandle(ProviderType), _key.InternalKeyHandle);

			_hashHmacHandle.TryDispose();

			_hashHmacHandle = hashHmacHandle;
		}

		[SecurityCritical]
		private byte[] ComputeHash(byte[] buffer)
		{
			CryptoApiHelper.HashData(_hashHmacHandle, buffer, 0, buffer.Length);

			return CryptoApiHelper.EndHashData(_hashHmacHandle);
		}


		/// <inheritdoc />
		protected override void Dispose(bool disposing)
		{
			_key.Clear();
			_hashHmacHandle.TryDispose();
		}
	}
}