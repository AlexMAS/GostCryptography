using System;
using System.Security;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;

namespace GostCryptography.Gost_R3411
{
	/// <summary>
	/// Базовый класс для всех реализаций генератора псевдослучайной последовательности (Pseudorandom Function, PRF) на базе алгоритма хэширования ГОСТ Р 34.11.
	/// </summary>
	/// <typeparam name="THMAC">Тип HMAC.</typeparam>
	public abstract class Gost_R3411_PRF<THMAC> : GostPRF where THMAC : GostHMAC
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
		protected Gost_R3411_PRF(ProviderType providerType, byte[] key, byte[] label, byte[] seed)
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
		private Gost_R3411_PRF(ProviderType providerType, Gost_28147_89_SymmetricAlgorithm key, byte[] label, byte[] seed) : base(providerType)
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
			_hmac = CreateHMAC(key);

			var labelAndSeed = new byte[label.Length + seed.Length];
			label.CopyTo(labelAndSeed, 0);
			seed.CopyTo(labelAndSeed, label.Length);

			_labelAndSeed = labelAndSeed;
			_buffer = new byte[labelAndSeed.Length + (_hmac.HashSize / 8)];

			_value = labelAndSeed;
			_keyIndex = 0;
		}


		private readonly Gost_28147_89_SymmetricAlgorithm _key;
		private readonly GostHMAC _hmac;
		private readonly byte[] _labelAndSeed;
		private readonly byte[] _buffer;
		private byte[] _value;
		private int _keyIndex;


		/// <summary>
		/// Создает экземпляр <typeparamref name="THMAC"/> на основе заданного ключа.
		/// </summary>
		[SecuritySafeCritical]
		protected abstract THMAC CreateHMAC(Gost_28147_89_SymmetricAlgorithm key);


		/// <summary>
		/// Возвращает очередной набор псевдослучайной последовательности.
		/// </summary>
		/// <remarks>
		/// Размер последовательности зависит от алгоритма хэширования.
		/// </remarks>
		[SecurityCritical]
		public byte[] DeriveBytes()
		{
			var randomBuffer = GenerateNextBytes();

			return _hmac.ComputeHash(randomBuffer);
		}


		/// <summary>
		/// Возвращает псевдослучайный симметричный ключ ГОСТ 28147.
		/// </summary>
		[SecuritySafeCritical]
		public Gost_28147_89_SymmetricAlgorithmBase DeriveKey()
		{
			var randomPassword = GenerateNextBytes();

			using (var hmac = CreateHMAC(_key))
			{
				return Gost_28147_89_SymmetricAlgorithm.CreateFromPassword(hmac, randomPassword);
			}
		}

		/// <summary>
		/// Возвращает псевдослучайный симметричный ключ ГОСТ 28147.
		/// </summary>
		/// <param name="position">Позиция ключа в псевдослучайной последовательности.</param>
		/// <exception cref="ArgumentOutOfRangeException">Если позиция ключа <paramref name="position"/> не кратна размеру ключа в байтах или ключ с данной позицией уже был создан.</exception>
		[SecurityCritical]
		public Gost_28147_89_SymmetricAlgorithmBase DeriveKey(int position)
		{
			if ((position % _hmac.HashSize) != 0)
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(position));
			}

			var keyIndex = position / _hmac.HashSize;

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
		private byte[] GenerateNextBytes()
		{
			_value = _hmac.ComputeHash(_value);
			_value.CopyTo(_buffer, 0);
			_labelAndSeed.CopyTo(_buffer, _value.Length);

			_keyIndex++;

			return _buffer;
		}


		/// <inheritdoc />
		protected override void Dispose(bool disposing)
		{
			_key.Clear();
			_hmac.Dispose();
		}
	}
}