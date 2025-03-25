using Radzen;
using Microsoft.AspNetCore.Components;

namespace Flic
{
    public partial class NorthwindService
    {
        private readonly NavigationManager navigationManager;
        
        public NorthwindService(NavigationManager navigationManager)
        {
            this.navigationManager = navigationManager;
        }

        public void Export(string table, string type, Query query = null)
        {
            var url = query != null ? query.ToUrl($"/export/{table}/{type}") : $"/export/{table}/{type}";
            navigationManager.NavigateTo(url, true);
        }
        public void Export2(string table, string type, Query query = null, string ma="")
        {
            var url = query != null ? query.ToUrl($"/export/{table}/{type}/{ma}") : $"/export/{table}/{type}/{ma}";
            navigationManager.NavigateTo(url, true);
        }

        public void ExportDSDK(string table, string type, Query query = null, string ma = "")
        {
            var url = query != null ? query.ToUrl($"/export/{table}/{type}/{ma}") : $"/export/{table}/{type}/{ma}";
            navigationManager.NavigateTo(url, true);
        }
    }
}
