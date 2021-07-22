using System;
using System.Collections.Generic;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Text;

namespace GostCryptography.Native
{
    class LinuxCryptoProNativeApi
    {

        #region Для работы с криптографическим провайдером

        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CertCloseStore(SafeStore hCertStore, uint dwFlags);

        [DllImport("libcapi20", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CertCreateCertificateContext(
            uint dwCertEncodingType,
            byte[] pCertEncoded,
            int cbCertEncoded
        );

        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptImportPublicKeyInfo(
          [In] SafeProvHandleImpl hCryptProv,
          [In] uint dwCertEncodingType,
          [In] IntPtr pSubjectPublicKeyInfo,
          [Out][In] ref SafeKeyHandleImpl phKey
        );

        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CertGetCertificateContextProperty(
        [In]IntPtr pCertContext,
        [In]uint dwPropId,
        [Out]IntPtr pvData,
        [In][Out]ref uint pcbData);

        [DllImport("libcapi20", SetLastError = true)]
        public static extern SafeStore CertOpenSystemStore(
        SafeStore hCertStore,
        [MarshalAs(UnmanagedType.LPStr)]string pszStoreName);

        [DllImport("libcapi20", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr CertOpenStore(
            [In]uint lpszStoreProvider,
            [In]uint dwEncodingType,
            [In]IntPtr hCryptProv, //HCRYPTPROV_LEGACY
            [In]int dwFlags,
            [In]StringBuilder pvPara //const void*
            );

        [DllImport("libcapi20", SetLastError = true)]
        public static extern IntPtr CertEnumCertificatesInStore(
            [In]SafeStore hCertStore,
            [In]IntPtr pPrevCertContext);

        [DllImport("libcapi20", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern uint CertGetNameString(
            [In]IntPtr pCertContext,
            uint dwType,
            uint dvFlags,
            IntPtr pvTypePara,
            byte[] pszNameString,
            uint cchNameString);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptAcquireContext([In] [Out] ref SafeProvHandleImpl hProv, [In] IntPtr pszContainer, [In] IntPtr pszProvider, [In] uint dwProvType, [In] uint dwFlags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptReleaseContext(IntPtr hCryptProv, uint dwFlags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [DllImport("libcapi20", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern bool CryptContextAddRef([In] IntPtr hProv, [In] byte[] pdwReserved, [In] uint dwFlags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CryptGetProvParam([In] SafeProvHandleImpl hProv, [In] uint dwParam, [In] [Out] byte[] pbData, ref uint dwDataLen, [In] uint dwFlags);

        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptGetProvParam([In]SafeProvHandleImpl hProv, [In] uint dwParam, [MarshalAs(UnmanagedType.LPStr)] StringBuilder pbData, ref uint dwDataLen, uint dwFlags);

        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptGetProvParam([In]SafeProvHandleImpl hProv, [In] uint dwParam, [MarshalAs(UnmanagedType.U8)] long pbData, ref uint dwDataLen, uint dwFlags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptSetProvParam([In] SafeProvHandleImpl hProv, [In] uint dwParam, [In] IntPtr pbData, [In] uint dwFlags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [DllImport("libcapi20", EntryPoint = "CryptSetProvParam", SetLastError = true)]
        public static extern bool CryptSetProvParam2(IntPtr hCryptProv, [In] uint dwParam, [In] byte[] pbData, [In] uint dwFlags);

        #endregion


        #region Для работы с функцией хэширования криптографического провайдера

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptCreateHash([In] SafeProvHandleImpl hProv, [In] uint Algid, [In] SafeKeyHandleImpl hKey, [In] uint dwFlags, [In] [Out] ref SafeHashHandleImpl phHash);

        [return: MarshalAs(UnmanagedType.Bool)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptDestroyHash(IntPtr pHashCtx);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptGetHashParam([In] SafeHashHandleImpl hHash, [In] uint dwParam, [In] [Out] byte[] pbData, ref uint pdwDataLen, [In] uint dwFlags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptSetHashParam([In] SafeHashHandleImpl hHash, [In] uint dwParam, [In] [Out] byte[] pbData, [In] uint dwFlags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptHashData([In] SafeHashHandleImpl hHash, [In] [Out] byte[] pbData, [In] uint dwDataLen, [In] uint dwFlags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern unsafe bool CryptHashData([In] SafeHashHandleImpl hHash, byte* pbData, [In] uint dwDataLen, [In] uint dwFlags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptHashSessionKey([In] SafeHashHandleImpl hHash, [In] SafeKeyHandleImpl hKey, [In] uint dwFlags);

        #endregion


        #region Для работы с функцией шифрования криптографического провайдера

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptDecrypt([In] SafeKeyHandleImpl hKey, [In] SafeHashHandleImpl hHash, [In] [MarshalAs(UnmanagedType.Bool)] bool Final, [In] uint dwFlags, [In] [Out] byte[] pbData, ref uint pdwDataLen);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptEncrypt([In] SafeKeyHandleImpl hKey, [In] SafeHashHandleImpl hHash, [In] [MarshalAs(UnmanagedType.Bool)] bool Final, [In] uint dwFlags, [In] [Out] byte[] pbData, ref uint pdwDataLen, [In] uint dwBufLen);

        #endregion


        #region Для работы с ключами криптографического провайдера

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptGenKey([In] SafeProvHandleImpl hProv, [In] uint Algid, [In] uint dwFlags, [In] [Out] ref SafeKeyHandleImpl phKey);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptGetUserKey([In] SafeProvHandleImpl hProv, [In] uint dwKeySpec, [In] [Out] ref SafeKeyHandleImpl phUserKey);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptDeriveKey([In] SafeProvHandleImpl hProv, [In] uint Algid, [In] SafeHashHandleImpl hBaseData, [In] uint dwFlags, [In] [Out] ref SafeKeyHandleImpl phKey);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptDuplicateKey([In] IntPtr hKey, [In] byte[] pdwReserved, [In] uint dwFlags, [In] [Out] ref SafeKeyHandleImpl phKey);

        [return: MarshalAs(UnmanagedType.Bool)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptDestroyKey(IntPtr pKeyCtx);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptGetKeyParam([In] SafeKeyHandleImpl hKey, [In] uint dwParam, [In] [Out] byte[] pbData, ref uint pdwDataLen, [In] uint dwFlags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptSetKeyParam([In] SafeKeyHandleImpl hKey, [In] uint dwParam, [In] byte[] pbData, [In] uint dwFlags);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptExportKey([In] SafeKeyHandleImpl hKey, [In] SafeKeyHandleImpl hExpKey, [In] uint dwBlobType, [In] uint dwFlags, [Out] byte[] pbData, ref uint pdwDataLen);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", SetLastError = true)]
        public static extern bool CryptImportKey([In] SafeProvHandleImpl hCryptProv, [In] byte[] pbData, [In] uint dwDataLen, [In] SafeKeyHandleImpl hPubKey, [In] uint dwFlags, [In] [Out] ref SafeKeyHandleImpl phKey);

        #endregion


        #region Для работы с цифровой подписью

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern bool CryptSignHash([In] SafeHashHandleImpl hHash, [In] uint dwKeySpec, IntPtr sDescription, [In] uint dwFlags, [In] [Out] byte[] pbSignature, ref uint pdwSigLen);

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("libcapi20", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern bool CryptVerifySignature([In] SafeHashHandleImpl hHash, [In] [Out] byte[] pbSignature, uint pdwSigLen, [In] SafeKeyHandleImpl hPubKey, IntPtr sDescription, [In] uint dwFlags);

        #endregion
    }
}
