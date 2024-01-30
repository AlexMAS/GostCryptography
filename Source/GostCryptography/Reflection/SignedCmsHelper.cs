using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography.Pkcs;

using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.Reflection
{
    static class SignedCmsHelper
    {
        private const string MessageHandleFieldName = "m_safeCryptMsgHandle";

        private static readonly Lazy<FieldInfo> MessageHandleField = new Lazy<FieldInfo>(() =>
        {
            var field = typeof(SignedCms).GetField(MessageHandleFieldName, BindingFlags.Instance | BindingFlags.NonPublic);
            return field ?? throw ExceptionUtility.CryptographicException(Resources.SignedCmsCannotFindPrivateMember, MessageHandleFieldName);
        });

        [SecuritySafeCritical]
        private static SafeHandle GetMessageHandle(SignedCms signedCms)
        {
            return MessageHandleField.Value.GetValue(signedCms) as SafeHandle;
        }

        [SecuritySafeCritical]
        public static void RemoveCertificates(this SignedCms signedCms)
        {
            var messageHandle = GetMessageHandle(signedCms);

            if (messageHandle == null)
            {
                return;
            }

            var certCount = signedCms.Certificates.Count;

            if (certCount == 0)
            {
                return;
            }

            for (var i = 0; i < certCount; ++i)
            {
                CryptoApiHelper.RemoveCertificate(messageHandle, 0);
            }
        }
    }
}
