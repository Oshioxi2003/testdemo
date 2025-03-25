using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace Flic.Shared.Models
{
    public class ResponseItem
    {
        [Key]
        public string order { get; set; }
        public string code { get; set; }
        public string content  { get; set; }
        public double amount { get; set; }
        public string currency { get; set; }
        public string note { get; set; }

    }
    public class RequestVanTin
    {
        [Key]
        public int id { get; set; }
        public string requestId { get; set; }
        public string? providerId { get; set; }
        public string? merchantId { get; set; }
        public string? custType { get; set; }
        //Ma sinh vien hoac ma nhap hoc
        public string custCode { get; set; }
        public string? channel { get; set; }
        public string? signature { get; set; }
        public string? timeRequest { get; set; }
    }
    public class ResponseVanTin
    {
        [Key]
        public int id { get; set; }
        public string requestId { get; set; }
        public string? providerId { get; set; }

        public string? merchantId { get; set; }

        public string? transTime { get; set; }
        public string? custType { get; set; }
        public string custCode { get; set; }
        public string custName { get; set; }
        public string? address { get; set; }
        public string? birthday { get; set; }
        public string? addInfor1 { get; set; }
        public string? addInfor2 { get; set; }
        public string? addInfor3 { get; set; }
        public string? responseCode { get; set; }
        public string? responseDesc { get; set; }
        public string? signature { get; set; }
        public string? primaryKeyId { get; set; }
        public string? items { get; set;}
        
    }
    public class ResponseVanTinView
    {
        [Key]
        //public int id { get; set; }
        public string requestId { get; set; }
        public string? providerId { get; set; }

        public string? merchantId { get; set; }

        public string? transTime { get; set; }
        public string? custType { get; set; }
        public string custCode { get; set; }
        public string custName { get; set; }
        public string? address { get; set; }
        public string? birthday { get; set; }
        public string? addInfor1 { get; set; }
        public string? addInfor2 { get; set; }
        public string? addInfor3 { get; set; }
        public string? responseCode { get; set; }
        public string? responseDesc { get; set; }
        public string? signature { get; set; }
        public string? primaryKeyId { get; set; }
        public List<ResponseItem> items { get; set; }
    }
    public class RequestGachNo
    {       
        [Key]
        public int id { get; set; }
        public string requestId { set; get; }
        public string? providerId { get; set; }
        public string? merchantId { get; set; }
        public string? primaryKeyId { set; get; }
        public string? custCode { set; get; }
        public string? custType { set; get; }
        public string? custName { set; get; }
        public string? address { get; set; }
        public string? birthday { get; set; }
        public string? phoneNo { set; get; }
        public string? idCard { get; set; }
        public string? addInfor1 { get; set; }
        public string? addInfor2 { get; set; }
        public string? addInfor3 { get; set; }
        public string? addInfor4 { get; set; }
        public string? addInfor5 { get; set; }
        public string? bankTransactionId { get; set; }
        public string? responseCode { get; set; }
        public string? responseDesc { get; set; }
        public string? transTime { get; set; }
        public string? channel { get; set; }
        public string? signature { get; set; }
        public string? items { get; set; }
        public DateTime timeUpdate { get; set; }
    }
    public class RequestGachNoView
    {
        [Key]
        public int id { get; set; }
        public string requestId { set; get; }
        public string? providerId { get; set; }
        public string? merchantId { get; set; }
        public string? primaryKeyId { set; get; }
        public string custCode { set; get; }
        public string? custType { set; get; }
        public string custName { set; get; }
        public string? address { get; set; }
        public string? birthday { get; set; }
        public string? phoneNo { set; get; }
        public string? idCard { get; set; }
        public string? addInfor1 { get; set; }
        public string? addInfor2 { get; set; }
        public string? addInfor3 { get; set; }
        public string? addInfor4 { get; set; }
        public string? addInfor5 { get; set; }
        public string? bankTransactionId { get; set; }
        public string? responseCode { get; set; }
        public string? responseDesc { get; set; }
        public string? transTime { get; set; }
        public string? channel { get; set; }
        public string? signature { get; set; }
        //public string? items { get; set; }
        public List<ResponseItem> items { get; set; }
    }
    public class ResponseGachNo
    {
        [Key]
        public int id { get; set; }
        public string requestId { get; set; }
        public string? providerId { get; set; }
        public string? merchantId { get; set; }
        public string? confirmTransactionId { get; set; }
        public string? transTime { get; set; }
        public string? responseCode { get; set; }
        public string? responseDesc { get; set; }
        public string? addInfo { get; set; }
        public string? signature { get; set; }
    }

}
