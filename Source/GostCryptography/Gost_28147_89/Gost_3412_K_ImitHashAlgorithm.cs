using System;
using System.Security;

using GostCryptography.Base;
using GostCryptography.Native;

namespace GostCryptography.Gost_28147_89
{
    /// <summary>
    /// Реализация функции вычисления имитовставки по ГОСТ Р 34.12-2015 Кузнечик.
    /// </summary>
    public sealed class Gost_3412_K_ImitHashAlgorithm : GostKeyedHashAlgorithm, ISafeHandleProvider<SafeHashHandleImpl>
    {
        /// <summary>
        /// Размер имитовставки ГОСТ Р 34.12-2015 Кузнечик.
        /// </summary>
        public const int DefaultHashSize = 64;

        /// <summary>
        /// Наименование алгоритма вычисления имитовставки ГОСТ Р 34.12-2015 Кузнечик.
        /// </summary>
        public const string AlgorithmNameValue = "id-tc26-cipher-gostr3412-2015-kuznyechik-imit";

        /// <summary>
        /// Известные наименования алгоритма вычисления имитовставки ГОСТ Р 34.12-2015 Кузнечик.
        /// </summary>
        public static readonly string[] KnownAlgorithmNames = { AlgorithmNameValue };


        /// <inheritdoc />
        [SecuritySafeCritical]
        public Gost_3412_K_ImitHashAlgorithm() : base(DefaultHashSize)
        {
            _keyAlgorithm = new Gost_3412_K_SymmetricAlgorithm(ProviderType);
        }

        /// <inheritdoc />
        [SecuritySafeCritical]
        public Gost_3412_K_ImitHashAlgorithm(ProviderType providerType) : base(providerType, DefaultHashSize)
        {
            _keyAlgorithm = new Gost_3412_K_SymmetricAlgorithm(ProviderType);
        }

        /// <summary>
        /// Конструктор.
        /// </summary>
        /// <param name="key">Ключ симметричного шифрования для подсчета имитовставки.</param>
        /// <exception cref="ArgumentNullException"></exception>
        [SecuritySafeCritical]
        public Gost_3412_K_ImitHashAlgorithm(Gost_3412_K_SymmetricAlgorithm key) : base(key.ProviderType, DefaultHashSize)
        {
            if (key == null)
            {
                throw ExceptionUtility.ArgumentNull(nameof(key));
            }

            KeyValue = null;

            _keyAlgorithm = Gost_3412_K_SymmetricAlgorithm.CreateFromKey(key);
        }


        [SecurityCritical]
        private Gost_3412_K_SymmetricAlgorithm _keyAlgorithm;

        [SecurityCritical]
        private SafeHashHandleImpl _hashHandle;


        /// <inheritdoc />
        public override string AlgorithmName => AlgorithmNameValue;


        /// <inheritdoc />
        SafeHashHandleImpl ISafeHandleProvider<SafeHashHandleImpl>.SafeHandle
        {
            [SecurityCritical]
            get { return _hashHandle; }
        }


        /// <inheritdoc />
        public override byte[] Key
        {
            [SecuritySafeCritical]
            get => _keyAlgorithm.Key;
            [SecuritySafeCritical]
            set => _keyAlgorithm.Key = value;
        }

        /// <inheritdoc />
        public Gost_3412_K_SymmetricAlgorithm KeyAlgorithm
        {
            [SecuritySafeCritical]
            get => Gost_3412_K_SymmetricAlgorithm.CreateFromKey(_keyAlgorithm);
            [SecuritySafeCritical]
            set => _keyAlgorithm = Gost_3412_K_SymmetricAlgorithm.CreateFromKey(value);
        }


        /// <inheritdoc />
        [SecuritySafeCritical]
        protected override void HashCore(byte[] data, int dataOffset, int dataLength)
        {
            if (_hashHandle == null)
            {
                InitHash();
            }

            CryptoApiHelper.HashData(_hashHandle, data, dataOffset, dataLength);
        }

        /// <inheritdoc />
        [SecuritySafeCritical]
        protected override byte[] HashFinal()
        {
            if (_hashHandle == null)
            {
                InitHash();
            }

            return CryptoApiHelper.EndHashData(_hashHandle);
        }

        [SecurityCritical]
        private void InitHash()
        {
            var providerHandle = CryptoApiHelper.GetProviderHandle(ProviderType);
            var hashHandle = CryptoApiHelper.CreateHashImit(providerHandle, _keyAlgorithm.GetSafeHandle(), Constants.CALG_GR3413_2015_K_IMIT);

            _hashHandle = hashHandle;
        }

        /// <inheritdoc />
        [SecuritySafeCritical]
        public override void Initialize()
        {
            _hashHandle.TryDispose();
            _hashHandle = null;
        }


        /// <inheritdoc />
        [SecuritySafeCritical]
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _keyAlgorithm?.Clear();
                _hashHandle.TryDispose();
            }

            base.Dispose(disposing);
        }
    }
}