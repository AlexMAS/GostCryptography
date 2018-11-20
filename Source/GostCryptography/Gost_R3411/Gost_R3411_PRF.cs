using System;
using System.Security;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;
using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.Gost_R3411
{
	/// <summary>
	/// Реализация алгоритма генерации псевдослучайной последовательности (Pseudorandom Function, PRF) ГОСТ Р 34.11.
	/// </summary>
	public class Gost_R3411_PRF : GostPRF, IDisposable
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerType">Тип криптографического провайдера.</param>
		/// <param name="label">Метка для порождения ключей (аргумент label функции PRF).</param>
		/// <param name="seed">Начальное число для порождения ключей (аргумент seed функции PRF).</param>
		/// <exception cref="ArgumentNullException"></exception>
		private Gost_R3411_PRF(int providerType, byte[] label, byte[] seed) : base(providerType)
		{
			if (label == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(label));
			}

			if (seed == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(seed));
			}

			var labelAndSeed = new byte[label.Length + seed.Length];
			label.CopyTo(labelAndSeed, 0);
			seed.CopyTo(labelAndSeed, label.Length);

			_labelAndSeed = labelAndSeed;
			_value = labelAndSeed;
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="key">Симметричный ключ ГОСТ 28147 для вычисления HMAC на основе алгоритма ГОСТ Р 34.11.</param>
		/// <param name="label">Метка для порождения ключей (аргумент label функции PRF).</param>
		/// <param name="seed">Начальное число для порождения ключей (аргумент seed функции PRF).</param>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
		public Gost_R3411_PRF(Gost_28147_89_SymmetricAlgorithmBase key, byte[] label, byte[] seed) : this(key.ProviderType, label, seed)
		{
			if (key == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(key));
			}

			_hashHmacHandle = SafeHashHandleImpl.InvalidHandle;
			_buffer = new byte[_labelAndSeed.Length + 32];

			_key = Gost_28147_89_SymmetricAlgorithm.CreateFromKey(key);
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
		public Gost_R3411_PRF(int providerType, byte[] key, byte[] label, byte[] seed) : this(providerType, label, seed)
		{
			if (key == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(key));
			}

			if (key.Length != 32)
			{
				throw ExceptionUtility.Argument(nameof(key), Resources.InvalidHashSize);
			}

			_hashHmacHandle = SafeHashHandleImpl.InvalidHandle;
			_buffer = new byte[_labelAndSeed.Length + 32];

			using (var keyHandle = CryptoApiHelper.ImportBulkSessionKey(CryptoApiHelper.GetProviderHandle(providerType), key, CryptoApiHelper.GetRandomNumberGenerator(providerType)))
			{
				_key = new Gost_28147_89_SymmetricAlgorithm(providerType, CryptoApiHelper.GetProviderHandle(providerType), keyHandle);
			}
		}


		private readonly Gost_28147_89_SymmetricAlgorithm _key;
		private readonly byte[] _labelAndSeed;
		private readonly byte[] _buffer;
		private int _keyIndex;

		[SecurityCritical]
		private SafeHashHandleImpl _hashHmacHandle;


		/// <summary>
		/// Возаращает 256 байт псевдослучайной последовательности.
		/// </summary>
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

			var symKeyHandle = CryptoApiHelper.DeriveSymKey(CryptoApiHelper.GetProviderHandle(ProviderType), _hashHmacHandle);

			return new Gost_28147_89_SymmetricAlgorithm(ProviderType, CryptoApiHelper.GetProviderHandle(ProviderType), symKeyHandle);
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


		private byte[] _value;

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
			var hashHmacHandle = CryptoApiHelper.CreateHashHmac(ProviderType, CryptoApiHelper.GetProviderHandle(ProviderType), _key.InternalKeyHandle);

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
		[SecuritySafeCritical]
		public void Dispose()
		{
			_key.Clear();

			_hashHmacHandle.TryDispose();

			GC.SuppressFinalize(this);
		}
	}
}