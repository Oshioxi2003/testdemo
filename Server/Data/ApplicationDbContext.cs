using Flic.Shared;
using Flic.Shared.Models;
using Flic.Shared.Models.TaiChinh;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Flic.Server.Data
{
    public class ApplicationDbContext : IdentityDbContext
    {
        public ApplicationDbContext(DbContextOptions options) : base(options)
        {
        }
        public virtual DbSet<Student> Students { get; set; }
        public virtual DbSet<Khoa> Khoas { get; set; }
        public virtual DbSet<Khoahoc> Khoahocs { get; set; }
        public virtual DbSet<LoaiKhoanthu> LoaiKhoanthus { get; set; }
        public virtual DbSet<Khoanthu> Khoanthus { get; set; }
        public virtual DbSet<ThuTien> ThuTiens { get; set; }
        public virtual DbSet<Nganh> Nganhs { get; set; }
        public virtual DbSet<Lop> Lops { get; set; }
        public virtual DbSet<KyThanhtoan> KyThanhtoans { get; set; }
        public virtual DbSet<StudentStatus> StudentStatuses { get; set; }
        public virtual DbSet<PhongKTX> PhongKTXs { get; set; }
        public virtual DbSet<SinhvienPhong> SinhvienPhongs { get; set; }

        public virtual DbSet<ResponseItem> ResponseItems {get; set; }
        public virtual DbSet<RequestVanTin> RequestVanTins { get; set; }
        public virtual DbSet<ResponseVanTin> ResponseVanTins { get; set; }
        public virtual DbSet<RequestGachNo> RequestGachNos { get; set; }
        public virtual DbSet<ResponseGachNo> ResponseGachNos { get; set; }
        public virtual DbSet<LogModel> LogModels { get; set; }

        /// <summary>
        /// 
        public virtual DbSet<DangkyTH03> DangkyTH03s { get; set; }
        public virtual DbSet<DMTinh> DMTinhs { get; set; }
        public virtual DbSet<DMDantoc> DMDantocs { get; set; }
        public virtual DbSet<Diemthi> Diemthis { get; set; }
        public virtual DbSet<Dotthi> Dotthis { get; set; }
        public virtual DbSet<Tin03_Trangthai> Tin03_Trangthais { get; set; }
        ///
        public virtual DbSet<LoaiLophoc> LoaiLophocs { get; set; }
        public virtual DbSet<Lophoc> Lophocs { get; set; }
        public virtual DbSet<DKHoc> DKHocs { get; set; }

        /// </summary>
        public virtual DbSet<Section> Sections { get; set; }
        public virtual DbSet<Article> Articles { get; set; }
        //
        public virtual DbSet<TAICHINH_MucChi> TAICHINH_MucChi { get; set; }
        public virtual DbSet<TAICHINH_NhomMuc> TAICHINH_NhomMuc { get; set; }
        public virtual DbSet<TAICHINH_DuTruKP> TAICHINH_DuTruKP { get; set; }
        /// 
        /// <param name="builder"></param>
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<IdentityRole>().HasData(new IdentityRole { Name = "User", NormalizedName = "USER", Id = Guid.NewGuid().ToString(), ConcurrencyStamp = Guid.NewGuid().ToString() });
            builder.Entity<IdentityRole>().HasData(new IdentityRole { Name = "Admin", NormalizedName = "ADMIN", Id = Guid.NewGuid().ToString(), ConcurrencyStamp = Guid.NewGuid().ToString() });
            builder.Entity<IdentityRole>().HasData(new IdentityRole { Name = "Student", NormalizedName = "TEACHER", Id = Guid.NewGuid().ToString(), ConcurrencyStamp = Guid.NewGuid().ToString() });
            builder.Entity<IdentityRole>().HasData(new IdentityRole { Name = "Manager", NormalizedName = "MANAGER", Id = Guid.NewGuid().ToString(), ConcurrencyStamp = Guid.NewGuid().ToString() });
            builder.Entity<IdentityRole>().HasData(new IdentityRole { Name = "Student", NormalizedName = "STUDENT", Id = Guid.NewGuid().ToString(), ConcurrencyStamp = Guid.NewGuid().ToString() });
        }
    }
}
