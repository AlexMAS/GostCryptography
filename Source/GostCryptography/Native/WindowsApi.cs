using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace GostCryptography.Native
{
    internal class WindowsApi : INativeApi
    {
        public bool CertCloseStore(SafeStore hCertStore, uint dwFlags)
        {
            return WindowsNativeApi.CertCloseStore(hCertStore, dwFlags);
        }

        public IntPtr CertEnumCertificatesInStore([In] SafeStore hCertStore, [In] IntPtr pPrevCertContext)
        {
            return WindowsNativeApi.CertEnumCertificatesInStore(hCertStore, pPrevCertContext);
        }

        public bool CertGetCertificateContextProperty([In] IntPtr pCertContext, [In] uint dwPropId, [Out] IntPtr pvData, [In, Out] ref uint pcbData)
        {
            return WindowsNativeApi.CertGetCertificateContextProperty(pCertContext, dwPropId, pvData, ref pcbData);
        }

        public uint CertGetNameString([In] IntPtr pCertContext, uint dwType, uint dwFlags, IntPtr pvTypePara, byte[] pszNameString, uint cchNameString)
        {
            return WindowsNativeApi.CertGetNameString(pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString);
        }

        public SafeStore CertOpenSystemStore(SafeStore hCertStore, string pszStoreName)
        {
            return WindowsNativeApi.CertOpenSystemStore(hCertStore, pszStoreName);
        }

        public bool CryptAcquireContext([In, Out] ref SafeProvHandleImpl hProv, [In] string pszContainer, [In] string pszProvider, [In] uint dwProvType, [In] uint dwFlags)
        {
            return WindowsNativeApi.CryptAcquireContext(ref hProv, pszContainer, pszProvider, dwProvType, dwFlags);
        }

        public bool CryptContextAddRef([In] IntPtr hProv, [In] byte[] pdwReserved, [In] uint dwFlags)
        {
            return WindowsNativeApi.CryptContextAddRef(hProv, pdwReserved, dwFlags);
        }

        public bool CryptCreateHash([In] SafeProvHandleImpl hProv, [In] uint Algid, [In] SafeKeyHandleImpl hKey, [In] uint dwFlags, [In, Out] ref SafeHashHandleImpl phHash)
        {
            return WindowsNativeApi.CryptCreateHash(hProv, Algid, hKey, dwFlags, ref phHash);
        }

        public bool CryptDecrypt([In] SafeKeyHandleImpl hKey, [In] SafeHashHandleImpl hHash, [In, MarshalAs(UnmanagedType.Bool)] bool Final, [In] uint dwFlags, [In, Out] byte[] pbData, ref uint pdwDataLen)
        {
            return WindowsNativeApi.CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, ref pdwDataLen);
        }

        public bool CryptDeriveKey([In] SafeProvHandleImpl hProv, [In] uint Algid, [In] SafeHashHandleImpl hBaseData, [In] uint dwFlags, [In, Out] ref SafeKeyHandleImpl phKey)
        {
            return WindowsNativeApi.CryptDeriveKey(hProv, Algid, hBaseData, dwFlags, ref phKey);
        }

        public bool CryptDestroyHash(IntPtr pHashCtx)
        {
            return WindowsNativeApi.CryptDestroyHash(pHashCtx);
        }

        public bool CryptDestroyKey(IntPtr pKeyCtx)
        {
            return WindowsNativeApi.CryptDestroyKey(pKeyCtx);
        }

        public bool CryptDuplicateKey([In] IntPtr hKey, [In] byte[] pdwReserved, [In] uint dwFlags, [In, Out] ref SafeKeyHandleImpl phKey)
        {
            return WindowsNativeApi.CryptDuplicateKey(hKey, pdwReserved, dwFlags, ref phKey);
        }

        public bool CryptEncrypt([In] SafeKeyHandleImpl hKey, [In] SafeHashHandleImpl hHash, [In, MarshalAs(UnmanagedType.Bool)] bool Final, [In] uint dwFlags, [In, Out] byte[] pbData, ref uint pdwDataLen, [In] uint dwBufLen)
        {
            return WindowsNativeApi.CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, ref pdwDataLen, dwBufLen);
        }

        public bool CryptExportKey([In] SafeKeyHandleImpl hKey, [In] SafeKeyHandleImpl hExpKey, [In] uint dwBlobType, [In] uint dwFlags, [Out] byte[] pbData, ref uint pdwDataLen)
        {
            return WindowsNativeApi.CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, ref pdwDataLen);
        }

        public bool CryptGenKey([In] SafeProvHandleImpl hProv, [In] uint Algid, [In] uint dwFlags, [In, Out] ref SafeKeyHandleImpl phKey)
        {
            return WindowsNativeApi.CryptGenKey(hProv, Algid, dwFlags, ref phKey);
        }

        public bool CryptGetHashParam([In] SafeHashHandleImpl hHash, [In] uint dwParam, [In, Out] byte[] pbData, ref uint pdwDataLen, [In] uint dwFlags)
        {
            return WindowsNativeApi.CryptGetHashParam(hHash, dwParam, pbData, ref pdwDataLen, dwFlags);
        }

        public bool CryptGetKeyParam([In] SafeKeyHandleImpl hKey, [In] uint dwParam, [In, Out] byte[] pbData, ref uint pdwDataLen, [In] uint dwFlags)
        {
            return WindowsNativeApi.CryptGetKeyParam(hKey, dwParam, pbData, ref pdwDataLen, dwFlags);
        }

        public bool CryptGetProvParam([In] SafeProvHandleImpl hProv, [In] uint dwParam, [In, Out] byte[] pbData, ref uint dwDataLen, [In] uint dwFlags)
        {
            return WindowsNativeApi.CryptGetProvParam(hProv, dwParam, pbData, ref dwDataLen, dwFlags);
        }

        public bool CryptGetProvParam([In] SafeProvHandleImpl hProv, [In] uint dwParam, [MarshalAs(UnmanagedType.LPStr)] StringBuilder pbData, ref uint dwDataLen, uint dwFlags)
        {
            return WindowsNativeApi.CryptGetProvParam(hProv, dwParam, pbData, ref dwDataLen, dwFlags);
        }

        public bool CryptGetProvParam([In] SafeProvHandleImpl hProv, [In] uint dwParam, [MarshalAs(UnmanagedType.U8)] long pbData, ref uint dwDataLen, uint dwFlags)
        {
            return WindowsNativeApi.CryptGetProvParam(hProv, dwParam, pbData, ref dwDataLen, dwFlags);
        }

        public bool CryptGetUserKey([In] SafeProvHandleImpl hProv, [In] uint dwKeySpec, [In, Out] ref SafeKeyHandleImpl phUserKey)
        {
            return WindowsNativeApi.CryptGetUserKey(hProv, dwKeySpec, ref phUserKey);
        }

        public bool CryptHashData([In] SafeHashHandleImpl hHash, [In, Out] byte[] pbData, [In] uint dwDataLen, [In] uint dwFlags)
        {
            return WindowsNativeApi.CryptHashData(hHash, pbData, dwDataLen, dwFlags);
        }

        public unsafe bool CryptHashData([In] SafeHashHandleImpl hHash, byte* pbData, [In] uint dwDataLen, [In] uint dwFlags)
        {
            return WindowsNativeApi.CryptHashData(hHash, pbData, dwDataLen, dwFlags);
        }

        public bool CryptHashSessionKey([In] SafeHashHandleImpl hHash, [In] SafeKeyHandleImpl hKey, [In] uint dwFlags)
        {
            return WindowsNativeApi.CryptHashSessionKey(hHash, hKey, dwFlags);
        }

        public bool CryptImportKey([In] SafeProvHandleImpl hCryptProv, [In] byte[] pbData, [In] uint dwDataLen, [In] SafeKeyHandleImpl hPubKey, [In] uint dwFlags, [In, Out] ref SafeKeyHandleImpl phKey)
        {
            return WindowsNativeApi.CryptImportKey(hCryptProv, pbData, dwDataLen, hPubKey, dwFlags, ref phKey);
        }

        public bool CryptImportPublicKeyInfo([In] SafeProvHandleImpl hCryptProv, [In] uint dwCertEncodingType, [In] /*CERT_PUBLIC_KEY_INFO*/ IntPtr pSubjectPublicKeyInfo, [Out][In] ref SafeKeyHandleImpl phKey)
        {
            return WindowsNativeApi.CryptImportPublicKeyInfo(hCryptProv, dwCertEncodingType, pSubjectPublicKeyInfo, ref phKey);
        }

        public bool CryptReleaseContext(IntPtr hCryptProv, uint dwFlags)
        {
            return WindowsNativeApi.CryptReleaseContext(hCryptProv, dwFlags);
        }

        public bool CryptSetHashParam([In] SafeHashHandleImpl hHash, [In] uint dwParam, [In, Out] byte[] pbData, [In] uint dwFlags)
        {
            return WindowsNativeApi.CryptSetHashParam(hHash, dwParam, pbData, dwFlags);
        }

        public bool CryptSetKeyParam([In] SafeKeyHandleImpl hKey, [In] uint dwParam, [In] byte[] pbData, [In] uint dwFlags)
        {
            return WindowsNativeApi.CryptSetKeyParam(hKey, dwParam, pbData, dwParam);
        }

        public bool CryptSetProvParam([In] SafeProvHandleImpl hProv, [In] uint dwParam, [In] IntPtr pbData, [In] uint dwFlags)
        {
            return WindowsNativeApi.CryptSetProvParam(hProv, dwParam, pbData, dwFlags);
        }

        public bool CryptSetProvParam2(IntPtr hCryptProv, [In] uint dwParam, [In] byte[] pbData, [In] uint dwFlags)
        {
            return WindowsNativeApi.CryptSetProvParam2(hCryptProv, dwParam, pbData, dwFlags);
        }

        public bool CryptSignHash([In] SafeHashHandleImpl hHash, [In] uint dwKeySpec, [MarshalAs(UnmanagedType.LPStr)] StringBuilder sDescription, [In] uint dwFlags, [In, Out] byte[] pbSignature, ref uint pdwSigLen)
        {
            return WindowsNativeApi.CryptSignHash(hHash, dwKeySpec, sDescription, dwFlags, pbSignature, ref pdwSigLen);
        }

        public bool CryptVerifySignature([In] SafeHashHandleImpl hHash, [In, Out] byte[] pbSignature, uint pdwSigLen, [In] SafeKeyHandleImpl hPubKey, [MarshalAs(UnmanagedType.LPStr)] StringBuilder sDescription, [In] uint dwFlags)
        {
            return WindowsNativeApi.CryptVerifySignature(hHash, pbSignature, pdwSigLen, hPubKey, sDescription, dwFlags);
        }

        public IntPtr CertCreateCertificateContext(
            uint dwCertEncodingType,
            byte[] pCertEncoded,
            int cbCertEncoded
        )
        {
            return WindowsNativeApi.CertCreateCertificateContext(dwCertEncodingType, pCertEncoded, cbCertEncoded);
        }
    }
}
