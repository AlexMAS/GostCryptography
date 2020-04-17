using GostCryptography.Base;
using System;
using System.Collections.Generic;
using System.Text;

namespace GostCryptography.Native
{
    abstract class NativeApiFactory
    {
        public abstract INativeApi CreateApi(ProviderType provider);
    }
}
