using System;
using System.Security;

using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Реализация алгоритма генерации псевдослучайной последовательности (Pseudorandom Function, PRF) по ГОСТ Р 34.11.
	/// </summary>
	public sealed class Gost3411Prf : IDisposable
	{
		/// <summary>
		/// URI алгоритма для использования в протоколе WS-Trust в качестве алгоритма вычисления ключа.
		/// </summary>
		public const string Gost3411PrfComputedKeyUrl = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:ck-p-gostr3411";

		/// <summary>
		/// URI алгоритма для использования в протоколах на базе WS-SecureCoveration.
		/// </summary>
		public const string Gost3411PrfKeyDerivationUrl = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:dk-p-gostr3411";


		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="label">Метка для порождения ключей (аргумент label функции PRF).</param>
		/// <param name="seed">Начальное число для порождения ключей (аргумент seed функции PRF).</param>
		/// <exception cref="ArgumentNullException"></exception>
		private Gost3411Prf(byte[] label, byte[] seed)
		{
			if (label == null)
			{
				throw ExceptionUtility.ArgumentNull("label");
			}

			if (seed == null)
			{
				throw ExceptionUtility.ArgumentNull("seed");
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
		public Gost3411Prf(Gost28147SymmetricAlgorithmBase key, byte[] label, byte[] seed)
			: this(label, seed)
		{
			if (key == null)
			{
				throw ExceptionUtility.ArgumentNull("key");
			}

			_hashHmacHandle = SafeHashHandleImpl.InvalidHandle;
			_buffer = new byte[_labelAndSeed.Length + 32];

			var gostSymmetricAlgorithm = key as Gost28147SymmetricAlgorithm;

			_key = (gostSymmetricAlgorithm != null)
				? new Gost28147SymmetricAlgorithm(gostSymmetricAlgorithm.InternalProvHandle, gostSymmetricAlgorithm.InternalKeyHandle)
				: new Gost28147SymmetricAlgorithm { Key = key.Key };
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="key">Симметричный ключ ГОСТ 28147 для вычисления HMAC на основе алгоритма ГОСТ Р 34.11.</param>
		/// <param name="label">Метка для порождения ключей (аргумент label функции PRF).</param>
		/// <param name="seed">Начальное число для порождения ключей (аргумент seed функции PRF).</param>
		/// <exception cref="ArgumentException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
		public Gost3411Prf(byte[] key, byte[] label, byte[] seed)
			: this(label, seed)
		{
			if (key == null)
			{
				throw ExceptionUtility.ArgumentNull("key");
			}

			if (key.Length != 32)
			{
				throw ExceptionUtility.Argument("key", Resources.InvalidHashSize);
			}

			_hashHmacHandle = SafeHashHandleImpl.InvalidHandle;
			_buffer = new byte[_labelAndSeed.Length + 32];

			using (var keyHandle = CryptoApiHelper.ImportBulkSessionKey(CryptoApiHelper.ProviderHandle, key, CryptoApiHelper.RandomNumberGenerator))
			{
				_key = new Gost28147SymmetricAlgorithm(CryptoApiHelper.ProviderHandle, keyHandle);
			}
		}


		private readonly Gost28147SymmetricAlgorithm _key;
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
		public Gost28147SymmetricAlgorithmBase DeriveKey()
		{
			GenerateNextBytes();

			var symKeyHandle = CryptoApiHelper.DeriveSymKey(CryptoApiHelper.ProviderHandle, _hashHmacHandle);

			return new Gost28147SymmetricAlgorithm(CryptoApiHelper.ProviderHandle, symKeyHandle);
		}

		/// <summary>
		/// Возвращает псевдослучайный симметричный ключ ГОСТ 28147.
		/// </summary>
		/// <param name="position">Позиция ключа в псевдослучайной последовательности.</param>
		/// <exception cref="ArgumentOutOfRangeException">Если позиция ключа <paramref name="position"/> не кратна 256 или ключ с требуемой позицией уже был создан.</exception>
		[SecurityCritical]
		public Gost28147SymmetricAlgorithmBase DeriveKey(int position)
		{
			if ((position % 256) != 0)
			{
				throw ExceptionUtility.ArgumentOutOfRange("position");
			}

			var keyIndex = position / 256;

			if (keyIndex < _keyIndex)
			{
				throw ExceptionUtility.ArgumentOutOfRange("position");
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
			var hashHmacHandle = CryptoApiHelper.CreateHashHmac(CryptoApiHelper.ProviderHandle, _key.InternalKeyHandle);

			_hashHmacHandle.TryDispose();

			_hashHmacHandle = hashHmacHandle;
		}

		[SecurityCritical]
		private byte[] ComputeHash(byte[] buffer)
		{
			CryptoApiHelper.HashData(_hashHmacHandle, buffer, 0, buffer.Length);

			return CryptoApiHelper.EndHashData(_hashHmacHandle);
		}


		[SecuritySafeCritical]
		public void Dispose()
		{
			_key.Clear();

			_hashHmacHandle.TryDispose();

			GC.SuppressFinalize(this);
		}
	}
}