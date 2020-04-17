using GostCryptography.Base;
using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace GostCryptography.Native
{
    /// <summary>
    /// Функции для работы с Microsoft CryptoAPI.
    /// </summary>
    [SecurityCritical]
    internal static class CryptoApi
    {
        private static INativeApi _api;

        internal static ProviderType ProviderType { get; set; }
        internal static NativeApiFactory Factory { get; set; }
        public static INativeApi Api
        {
            get
            {
                return Factory.CreateApi(ProviderType);
            }
        }

        public static bool CertCloseStore(SafeStore hCertStore, uint dwFlags)
        {
            return Api.CertCloseStore(hCertStore, dwFlags);
        }

        public static bool CryptAcquireContext(ref SafeProvHandleImpl hProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags)
        {
            return Api.CryptAcquireContext(ref hProv, pszContainer, pszProvider, dwProvType, dwFlags);
        }

        public static bool CryptContextAddRef(IntPtr hProv, byte[] pdwReserved, uint dwFlags)
        {
            return Api.CryptContextAddRef(hProv, pdwReserved, dwFlags);
        }

        public static bool CryptCreateHash(SafeProvHandleImpl hProv, uint Algid, SafeKeyHandleImpl hKey, uint dwFlags, ref SafeHashHandleImpl phHash)
        {
            return Api.CryptCreateHash(hProv, Algid, hKey, dwFlags, ref phHash);
        }

        public static bool CryptDecrypt(SafeKeyHandleImpl hKey, SafeHashHandleImpl hHash, bool Final, uint dwFlags, byte[] pbData, ref uint pdwDataLen)
        {
            return Api.CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, ref pdwDataLen);
        }

        public static bool CryptDeriveKey(SafeProvHandleImpl hProv, uint Algid, SafeHashHandleImpl hBaseData, uint dwFlags, ref SafeKeyHandleImpl phKey)
        {
            return Api.CryptDeriveKey(hProv, Algid, hBaseData, dwFlags, ref phKey);
        }

        public static bool CryptDestroyHash(IntPtr pHashCtx)
        {
            return Api.CryptDestroyHash(pHashCtx);
        }

        public static bool CryptDestroyKey(IntPtr pKeyCtx)
        {
            return Api.CryptDestroyKey(pKeyCtx);
        }

        public static bool CryptDuplicateKey(IntPtr hKey, byte[] pdwReserved, uint dwFlags, ref SafeKeyHandleImpl phKey)
        {
            return Api.CryptDuplicateKey(hKey, pdwReserved, dwFlags, ref phKey);
        }

        public static bool CryptEncrypt(SafeKeyHandleImpl hKey, SafeHashHandleImpl hHash, bool Final, uint dwFlags, byte[] pbData, ref uint pdwDataLen, uint dwBufLen)
        {
            return Api.CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, ref pdwDataLen, dwBufLen);
        }

        public static bool CryptExportKey(SafeKeyHandleImpl hKey, SafeKeyHandleImpl hExpKey, uint dwBlobType, uint dwFlags, byte[] pbData, ref uint pdwDataLen)
        {
            return Api.CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, ref pdwDataLen);
        }

        public static bool CryptGenKey(SafeProvHandleImpl hProv, uint Algid, uint dwFlags, ref SafeKeyHandleImpl phKey)
        {
            return Api.CryptGenKey(hProv, Algid, dwFlags, ref phKey);
        }

        public static bool CryptGetHashParam(SafeHashHandleImpl hHash, uint dwParam, byte[] pbData, ref uint pdwDataLen, uint dwFlags)
        {
            return Api.CryptGetHashParam(hHash, dwParam, pbData, ref pdwDataLen, dwFlags);
        }

        public static bool CryptGetKeyParam(SafeKeyHandleImpl hKey, uint dwParam, byte[] pbData, ref uint pdwDataLen, uint dwFlags)
        {
            return Api.CryptGetKeyParam(hKey, dwParam, pbData, ref pdwDataLen, dwFlags);
        }

        public static bool CryptGetProvParam(SafeProvHandleImpl hProv, uint dwParam, byte[] pbData, ref uint dwDataLen, uint dwFlags)
        {
            return Api.CryptGetProvParam(hProv, dwParam, pbData, ref dwDataLen, dwFlags);
        }

        public static bool CryptGetProvParam(SafeProvHandleImpl hProv, uint dwParam, StringBuilder pbData, ref uint dwDataLen, uint dwFlags)
        {
            return Api.CryptGetProvParam(hProv, dwParam, pbData, ref dwDataLen, dwFlags);
        }

        public static bool CryptGetProvParam(SafeProvHandleImpl hProv, uint dwParam, long pbData, ref uint dwDataLen, uint dwFlags)
        {
            return Api.CryptGetProvParam(hProv, dwParam, pbData, ref dwDataLen, dwFlags);
        }

        public static bool CryptGetUserKey(SafeProvHandleImpl hProv, uint dwKeySpec, ref SafeKeyHandleImpl phUserKey)
        {
            return Api.CryptGetUserKey(hProv, dwKeySpec, ref phUserKey);
        }

        public static bool CryptHashData(SafeHashHandleImpl hHash, byte[] pbData, uint dwDataLen, uint dwFlags)
        {
            return Api.CryptHashData(hHash, pbData, dwDataLen, dwFlags);
        }

        public static unsafe bool CryptHashData(SafeHashHandleImpl hHash, byte* pbData, uint dwDataLen, uint dwFlags)
        {
            return Api.CryptHashData(hHash, pbData, dwDataLen, dwFlags);
        }

        public static bool CryptHashSessionKey(SafeHashHandleImpl hHash, SafeKeyHandleImpl hKey, uint dwFlags)
        {
            return Api.CryptHashSessionKey(hHash, hKey, dwFlags);
        }

        public static bool CryptImportKey(SafeProvHandleImpl hCryptProv, byte[] pbData, uint dwDataLen, SafeKeyHandleImpl hPubKey, uint dwFlags, ref SafeKeyHandleImpl phKey)
        {
            return Api.CryptImportKey(hCryptProv, pbData, dwDataLen, hPubKey, dwFlags, ref phKey);
        }

        public static bool CryptReleaseContext(IntPtr hCryptProv, uint dwFlags)
        {
            return Api.CryptReleaseContext(hCryptProv, dwFlags);
        }

        public static bool CryptSetHashParam(SafeHashHandleImpl hHash, uint dwParam, byte[] pbData, uint dwFlags)
        {
            return Api.CryptSetHashParam(hHash, dwParam, pbData, dwFlags);
        }

        public static bool CryptSetKeyParam(SafeKeyHandleImpl hKey, uint dwParam, byte[] pbData, uint dwFlags)
        {
            return Api.CryptSetKeyParam(hKey, dwParam, pbData, dwParam);
        }

        public static bool CryptSetProvParam(SafeProvHandleImpl hProv, uint dwParam, IntPtr pbData, uint dwFlags)
        {
            return Api.CryptSetProvParam(hProv, dwParam, pbData, dwFlags);
        }

        public static bool CryptSetProvParam2(IntPtr hCryptProv, uint dwParam, byte[] pbData, uint dwFlags)
        {
            return Api.CryptSetProvParam2(hCryptProv, dwParam, pbData, dwFlags);
        }

        public static bool CryptSignHash(SafeHashHandleImpl hHash, uint dwKeySpec, StringBuilder sDescription, uint dwFlags, byte[] pbSignature, ref uint pdwSigLen)
        {
            return Api.CryptSignHash(hHash, dwKeySpec, sDescription, dwFlags, pbSignature, ref pdwSigLen);
        }

        public static bool CryptVerifySignature(SafeHashHandleImpl hHash, byte[] pbSignature, uint pdwSigLen, SafeKeyHandleImpl hPubKey, StringBuilder sDescription, uint dwFlags)
        {
            return Api.CryptVerifySignature(hHash, pbSignature, pdwSigLen, hPubKey, sDescription, dwFlags);
        }

        public static SafeStore CertOpenSystemStore(SafeStore hCertStore, string pszStoreName)
        {
            return Api.CertOpenSystemStore(hCertStore, pszStoreName);
        }

        public static IntPtr CertEnumCertificatesInStore(SafeStore hCertStore, IntPtr pPrevCertContext)
        {
            return Api.CertEnumCertificatesInStore(hCertStore, pPrevCertContext);
        }

        public static uint CertGetNameString(IntPtr pCertContext, uint dwType, uint dwFlags, IntPtr pvTypePara, byte[] pszNameString, uint cchNameString)
        {
            return Api.CertGetNameString(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString);
        }

        public static bool CertGetCertificateContextProperty(IntPtr pCertContext, uint dwPropId, IntPtr pvData, ref uint pcbData)
        {
            return Api.CertGetCertificateContextProperty(pCertContext, dwPropId, pvData, ref pcbData);
        }

        public static bool CryptImportPublicKeyInfo([In] SafeProvHandleImpl hCryptProv,
          [In] uint dwCertEncodingType,
          [In] IntPtr pSubjectPublicKeyInfo,
          [Out][In]ref SafeKeyHandleImpl phKey)
        {
            return Api.CryptImportPublicKeyInfo(hCryptProv, dwCertEncodingType, pSubjectPublicKeyInfo, ref phKey);
        }

        public static IntPtr CertCreateCertificateContext(uint dwCertEncodingType, byte[] pCertEncoded, int cbCertEncoded)
        {
            return Api.CertCreateCertificateContext(dwCertEncodingType, pCertEncoded, cbCertEncoded);
        }
    }
}