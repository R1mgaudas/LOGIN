using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Loginas.Models
{
    public class HashWithSaltResult
    {
        public string Salt { get; }
        public string Digest { get; set; }

        public HashWithSaltResult(string salt, string digest)
        {
            Salt = salt;
            Digest = digest;
        }
    }
}