using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Flic.Shared.Models
{
    public class VietQR
    {
        //sub field of consumerAccountInformation
        //public string BankGuid = "0010A000000727";
        //public string BNBID = "0006970422";
        //public string ConsumerID = "01100912371565";
        //public string serviceCode = "0208QRIBFTTA";
        //End sub field

        public string payloadFormatIndicator = "000201";
        public string pointOfInitiationMethod = "010212";        //
        public string consumerAccountInformation = "38540010A00000072701240006970422011009123715650208QRIBFTTA";        
        public string transactionCurrency = "5303704";
        public string transactionAmount;
        public string countryCode = "5802VN";

        public VietQR(string pl, string po, string conn, string tr, string cou) { 
            this.payloadFormatIndicator = pl;
            this.pointOfInitiationMethod = po;
            this.consumerAccountInformation = conn;
            this.transactionCurrency = tr;
            this.countryCode = cou;
        }

        public string additionalDataFieldTemplate = "";
        public string otherData="";
        //sub file of additional data field
        public string BillNumber { get; set; }//= "01";
        public string MobileNumber { get; set; }//= "02";
        public string StoreLabel { get; set; } //= "03";
        public string ReferenceLabel { get; set; } //= "06";
        public string CustomerLabel { get; set; } //= "07";
        public string PurposeOfTransaction { get; set; } //08; 
        public void builAdditionalData()
        {
            int totalLength = 0;
            string data = "";
            if(BillNumber!=null && BillNumber != "")
            {                
                data = data + "01" + BillNumber.Length.ToString("00") + BillNumber;
            }
            if (MobileNumber != null && MobileNumber != "")
            {             
                data = data + "02" + MobileNumber.Length.ToString("00") + MobileNumber;
            }
            if (StoreLabel != null && StoreLabel != "")
            {
                data = data + "03" + StoreLabel.Length.ToString("00") + StoreLabel;
            }
            if (ReferenceLabel != null && ReferenceLabel != "")
            {                
                data = data + "06" + ReferenceLabel.Length.ToString("00") + ReferenceLabel;
            }
            if (CustomerLabel != null && CustomerLabel != "")
            {             
                data = data + "07" + CustomerLabel.Length.ToString("00") + CustomerLabel;
            }
            if (PurposeOfTransaction != null && PurposeOfTransaction != "")
            {             
                data = data + "08" + PurposeOfTransaction.Length.ToString("00") + PurposeOfTransaction;
            }
            additionalDataFieldTemplate = "62" + data.Length.ToString("00") + data;
        }
        public void setBillNumber(string billNumber)
        {
            BillNumber = billNumber;
            builAdditionalData();            
        }
        public void setMobileNumber(string val)
        {
            MobileNumber = val;
            builAdditionalData();            
        }
        public void setStoreLabel(string val)
        {
            StoreLabel = val;
            builAdditionalData();            
        }
        public void setReferenceLabel(string val)
        {
            ReferenceLabel = val;
            builAdditionalData();            
        }
        public void setCustomerLabel(string val)
        {
            CustomerLabel = val;
            builAdditionalData();            
        }
        public void setPurposeOfTransaction(string val)
        {
            PurposeOfTransaction = val;
            builAdditionalData();            
        }
        //
        public string crc = "";
        //public VietQR() { }
        //000201
        //010211
        //38540010A000000727
        //01240006970422
        //01100912371565
        //0208QRIBFTTA
        //53037045802VN6304a7c2
        public void setTransactionAmount(string money)
        {
            var length = money.Length.ToString("00");
            this.transactionAmount = "54" + length + money;
        }
        public void setAdditionalDataFieldTemplate(string data)
        {
            var length = data.Length.ToString("00");
            this.additionalDataFieldTemplate = "62" + length + data;
        }
        public void setOther(string data)
        {
            //var length = data.Length.ToString("00");
            //this.otherData = data;
        }
        public ushort calcCRC(string dataString)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(dataString);
            ushort crc = 0xFFFF; // Initialize CRC value
            foreach (byte b in bytes)
            {
                crc ^= (ushort)(b << 8);
                for (int i = 0; i < 8; i++)
                {
                    if ((crc & 0x8000) != 0)
                    {
                        crc = (ushort)((crc << 1) ^ 0x1021);
                    }
                    else
                    {
                        crc <<= 1;
                    }
                }
            }
            return crc;
        }
        public string buidQR()
        {
            string contentQR = payloadFormatIndicator
                + pointOfInitiationMethod
                + consumerAccountInformation
                + transactionCurrency
                + transactionAmount
                + countryCode
                + additionalDataFieldTemplate
                //+ otherData
                + "6304";
            string crc = calcCRC(contentQR).ToString("X4").ToUpper();
            return contentQR + crc;
        }
    }
    
}
