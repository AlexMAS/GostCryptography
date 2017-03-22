using System.Security;

using GostCryptography.Native;

namespace GostCryptography.Cryptography
{
    /// <summary>
    /// Реализация алгоритма хэширования в соответствии с ГОСТ Р 34.11-94.
    /// </summary>
    public class Gost3411HashAlgorithm : Gost3411HashAlgorithmBase
    {
        [SecuritySafeCritical]
        public Gost3411HashAlgorithm()
        {
        }

        [SecuritySafeCritical]
        protected override SafeHashHandleImpl CreateHashHandle()
        {
            return CryptoApiHelper.CreateHash_3411_94(CryptoApiHelper.ProviderHandle);
        }
    }
}