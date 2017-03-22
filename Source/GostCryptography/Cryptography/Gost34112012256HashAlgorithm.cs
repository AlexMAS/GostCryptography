using System.Security;

using GostCryptography.Native;

namespace GostCryptography.Cryptography
{
    /// <summary>
    /// Реализация алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 256 бит.
    /// </summary>
    public class Gost34112012256HashAlgorithm : Gost3411HashAlgorithmBase
    {
        [SecuritySafeCritical]
        public Gost34112012256HashAlgorithm()
        {
        }

        [SecuritySafeCritical]
        protected override SafeHashHandleImpl CreateHashHandle()
        {
            return CryptoApiHelper.CreateHash_3411_2012_256(CryptoApiHelper.ProviderHandle);
        }
    }
}