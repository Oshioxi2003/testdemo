using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared
{
    public class RandomPassword
    {
        // Define default min and max password lengths.
        private static int DEFAULT_MIN_PASSWORD_LENGTH = 8;
        private static int DEFAULT_MAX_PASSWORD_LENGTH = 10;

        // Define supported password characters divided into groups.
        // You can add (or remove) characters to (from) these groups.
        private static string PASSWORD_CHARS_LCASE = "abcdefgijkmnopqrstwxyz";
        private static string PASSWORD_CHARS_UCASE = "ABCDEFGHJKLMNPQRSTWXYZ";
        private static string PASSWORD_CHARS_NUMERIC = "0123456789";
        private static string PASSWORD_CHARS_SPECIAL = "$&!%&";
        static string shuffle(string input)
        {
            var q = from c in input.ToCharArray()
                    orderby Guid.NewGuid()
                    select c;
            string s = string.Empty;
            foreach (var r in q)
                s += r;
            return s;
        }
        public static string CreateRandomPassword(int numUpper = 1, int numLower=3, int numDigit=3, int numSpecial=1)
        {            
            Random random = new Random();
            
            // Minimum size 8. Max size is number of all allowed chars.  
            int size = numUpper + numLower + numDigit + numSpecial;

            // Select one random character at a time from the string  
            // and create an array of chars  
            char[] chars = new char[size];
            for (int i = 0; i < numUpper; i++)
            {
                chars[i] = PASSWORD_CHARS_UCASE[random.Next(0, PASSWORD_CHARS_UCASE.Length)];
            }
            for (int i = numUpper; i < numUpper + numLower; i++)
            {
                chars[i] = PASSWORD_CHARS_LCASE[random.Next(0, PASSWORD_CHARS_LCASE.Length)];
            }
            for (int i = numUpper + numLower; i < numUpper + numLower + numDigit; i++)
            {
                chars[i] = PASSWORD_CHARS_NUMERIC[random.Next(0, PASSWORD_CHARS_NUMERIC.Length)];
            }
            for (int i = numUpper + numLower + numDigit; i < size; i++)
            {
                chars[i] = PASSWORD_CHARS_SPECIAL[random.Next(0, PASSWORD_CHARS_SPECIAL.Length)];
            }

            return shuffle(new string(chars));
        }
    }
}
