using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace GostCryptography.Native
{
    interface INativeApi
    {

        bool CryptAcquireContext([In] [Out] ref SafeProvHandleImpl hProv, [In] string pszContainer, [In] string pszProvider, [In] uint dwProvType, [In] uint dwFlags);

        bool CryptReleaseContext(IntPtr hCryptProv, uint dwFlags);

        bool CryptContextAddRef([In] IntPtr hProv, [In] byte[] pdwReserved, [In] uint dwFlags);

        bool CryptGetProvParam([In] SafeProvHandleImpl hProv, [In] uint dwParam, [In] [Out] byte[] pbData, ref uint dwDataLen, [In] uint dwFlags);

        bool CryptGetProvParam([In]SafeProvHandleImpl hProv, [In] uint dwParam, [MarshalAs(UnmanagedType.LPStr)] StringBuilder pbData, ref uint dwDataLen, uint dwFlags);

        bool CryptGetProvParam([In]SafeProvHandleImpl hProv, [In] uint dwParam, [MarshalAs(UnmanagedType.U8)] long pbData, ref uint dwDataLen, uint dwFlags);

        bool CryptSetProvParam([In] SafeProvHandleImpl hProv, [In] uint dwParam, [In] IntPtr pbData, [In] uint dwFlags);

        bool CryptSetProvParam2(IntPtr hCryptProv, [In] uint dwParam, [In] byte[] pbData, [In] uint dwFlags);

        bool CryptImportPublicKeyInfo(
          [In] SafeProvHandleImpl hCryptProv,
          [In] uint dwCertEncodingType,
          [In] IntPtr pPublicKeyInfo,
          [Out][In] ref SafeKeyHandleImpl phKey
        );

        SafeStore CertOpenSystemStore(SafeStore hCertStore, string pszStoreName);

        IntPtr CertEnumCertificatesInStore([In]SafeStore hCertStore, [In]IntPtr pPrevCertContext);

        uint CertGetNameString(
            [In]IntPtr pCertContext,
            uint dwType,
            uint dwFlags,
            IntPtr pvTypePara,
            byte[] pszNameString,
            uint cchNameString);

        bool CertGetCertificateContextProperty(
        [In]IntPtr pCertContext,
        [In]uint dwPropId,
        [Out]IntPtr pvData,
        [In][Out]ref uint pcbData);

        IntPtr CertCreateCertificateContext(
            uint dwCertEncodingType,
            byte[] pCertEncoded,
            int cbCertEncoded
        );

        bool CertCloseStore(SafeStore hCertStore, uint dwFlags);
        bool CryptCreateHash([In] SafeProvHandleImpl hProv, [In] uint Algid, [In] SafeKeyHandleImpl hKey, [In] uint dwFlags, [In] [Out] ref SafeHashHandleImpl phHash);

        bool CryptDestroyHash(IntPtr pHashCtx);

        bool CryptGetHashParam([In] SafeHashHandleImpl hHash, [In] uint dwParam, [In] [Out] byte[] pbData, ref uint pdwDataLen, [In] uint dwFlags);

        bool CryptSetHashParam([In] SafeHashHandleImpl hHash, [In] uint dwParam, [In] [Out] byte[] pbData, [In] uint dwFlags);

        bool CryptHashData([In] SafeHashHandleImpl hHash, [In] [Out] byte[] pbData, [In] uint dwDataLen, [In] uint dwFlags);

        unsafe bool CryptHashData([In] SafeHashHandleImpl hHash, byte* pbData, [In] uint dwDataLen, [In] uint dwFlags);

        bool CryptHashSessionKey([In] SafeHashHandleImpl hHash, [In] SafeKeyHandleImpl hKey, [In] uint dwFlags);


        bool CryptDecrypt([In] SafeKeyHandleImpl hKey, [In] SafeHashHandleImpl hHash, [In] [MarshalAs(UnmanagedType.Bool)] bool Final, [In] uint dwFlags, [In] [Out] byte[] pbData, ref uint pdwDataLen);

        bool CryptEncrypt([In] SafeKeyHandleImpl hKey, [In] SafeHashHandleImpl hHash, [In] [MarshalAs(UnmanagedType.Bool)] bool Final, [In] uint dwFlags, [In] [Out] byte[] pbData, ref uint pdwDataLen, [In] uint dwBufLen);

        bool CryptGenKey([In] SafeProvHandleImpl hProv, [In] uint Algid, [In] uint dwFlags, [In] [Out] ref SafeKeyHandleImpl phKey);

        bool CryptGetUserKey([In] SafeProvHandleImpl hProv, [In] uint dwKeySpec, [In] [Out] ref SafeKeyHandleImpl phUserKey);

        bool CryptDeriveKey([In] SafeProvHandleImpl hProv, [In] uint Algid, [In] SafeHashHandleImpl hBaseData, [In] uint dwFlags, [In] [Out] ref SafeKeyHandleImpl phKey);

        bool CryptDuplicateKey([In] IntPtr hKey, [In] byte[] pdwReserved, [In] uint dwFlags, [In] [Out] ref SafeKeyHandleImpl phKey);

        bool CryptDestroyKey(IntPtr pKeyCtx);

        bool CryptGetKeyParam([In] SafeKeyHandleImpl hKey, [In] uint dwParam, [In] [Out] byte[] pbData, ref uint pdwDataLen, [In] uint dwFlags);

        bool CryptSetKeyParam([In] SafeKeyHandleImpl hKey, [In] uint dwParam, [In] byte[] pbData, [In] uint dwFlags);

        bool CryptExportKey([In] SafeKeyHandleImpl hKey, [In] SafeKeyHandleImpl hExpKey, [In] uint dwBlobType, [In] uint dwFlags, [Out] byte[] pbData, ref uint pdwDataLen);

        bool CryptImportKey([In] SafeProvHandleImpl hCryptProv, [In] byte[] pbData, [In] uint dwDataLen, [In] SafeKeyHandleImpl hPubKey, [In] uint dwFlags, [In] [Out] ref SafeKeyHandleImpl phKey);


        bool CryptSignHash([In] SafeHashHandleImpl hHash, [In] uint dwKeySpec, [MarshalAs(UnmanagedType.LPStr)] StringBuilder sDescription, [In] uint dwFlags, [In] [Out] byte[] pbSignature, ref uint pdwSigLen);

        bool CryptVerifySignature([In] SafeHashHandleImpl hHash, [In] [Out] byte[] pbSignature, uint pdwSigLen, [In] SafeKeyHandleImpl hPubKey, [MarshalAs(UnmanagedType.LPStr)] StringBuilder sDescription, [In] uint dwFlags);

    }
}
