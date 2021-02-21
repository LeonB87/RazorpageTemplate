using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using RazorUsingGraphAPI.Helpers;
using Microsoft.Graph;
using System;
using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;

namespace RazorUsingGraphAPI.Graph
{
    public class GraphServiceExtension
    {
        private readonly IGraphServiceClient _client;

        private GraphServiceExtension(IGraphServiceClient client)
        {
            _client = client;
        }
        public static async Task<IEnumerable<string>> CheckMemberGroupsAsync(Dictionary<string, string> roleGroups, GraphServiceClient graphClient)
        {

            IEnumerable<String> groupIds = roleGroups.Keys;
            var batchSize = 20;

            var tasks = new List<Task<IDirectoryObjectCheckMemberGroupsCollectionPage>>();
            foreach (var groupsBatch in groupIds.Batch(batchSize))
            {
                tasks.Add(graphClient.Me.CheckMemberGroups(groupsBatch).Request().PostAsync());
            }
            await Task.WhenAll(tasks);

            var memberGroups = tasks.SelectMany(x => x.Result.ToList());

            return memberGroups;
        }
    }
}
