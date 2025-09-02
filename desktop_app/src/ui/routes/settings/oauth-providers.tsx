import { createFileRoute } from '@tanstack/react-router';
import { ExternalLink, Key, Loader2, Shield, Server } from 'lucide-react';
import { useEffect, useState } from 'react';

import { Badge } from '@ui/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@ui/components/ui/card';
import { Skeleton } from '@ui/components/ui/skeleton';
import { Separator } from '@ui/components/ui/separator';
import { listOAuthProviders } from '@ui/lib/clients/archestra/api/gen';

export const Route = createFileRoute('/settings/oauth-providers')({
  component: OAuthProviders,
});

function OAuthProviders() {
  const [providers, setProviders] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    const fetchProviders = async () => {
      try {
        setIsLoading(true);
        const response = await listOAuthProviders();
        if (response.error) {
          throw new Error(response.error.error || 'Failed to fetch OAuth providers');
        }
        setProviders(response.data || []);
      } catch (err) {
        setError(err instanceof Error ? err : new Error('Unknown error occurred'));
      } finally {
        setIsLoading(false);
      }
    };

    fetchProviders();
  }, []);

  if (isLoading) {
    return (
      <div className="space-y-4">
        {[1, 2, 3].map((i) => (
          <Card key={i}>
            <CardHeader>
              <Skeleton className="h-6 w-32" />
              <Skeleton className="h-4 w-64 mt-2" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-20 w-full" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <Card className="border-red-200 dark:border-red-900">
        <CardHeader>
          <CardTitle className="text-red-600 dark:text-red-400">Error Loading Providers</CardTitle>
          <CardDescription>{error instanceof Error ? error.message : 'Unknown error occurred'}</CardDescription>
        </CardHeader>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="mb-6">
        <h1 className="text-2xl font-bold mb-2">OAuth Providers</h1>
        <p className="text-muted-foreground">
          Available authentication providers for MCP servers. These providers enable secure access to external services.
        </p>
      </div>

      {providers?.map((provider) => (
        <Card key={provider.name} className="hover:shadow-md transition-shadow">
          <CardHeader>
            <div className="flex items-start justify-between">
              <div className="space-y-1">
                <CardTitle className="flex items-center gap-2">
                  <Key className="h-5 w-5" />
                  {provider.displayName}
                </CardTitle>
                <CardDescription className="text-sm">
                  Provider ID: <code className="bg-muted px-1 py-0.5 rounded text-xs">{provider.name}</code>
                </CardDescription>
              </div>
              <div className="flex gap-2">
                {provider.browserAuthEnabled && (
                  <Badge variant="secondary" className="gap-1">
                    <Shield className="h-3 w-3" />
                    Browser Auth
                  </Badge>
                )}
                {provider.supportsRefresh && <Badge variant="outline">Refresh Tokens</Badge>}
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <h4 className="text-sm font-semibold mb-2">OAuth Scopes</h4>
              <div className="flex flex-wrap gap-1">
                {provider.scopes?.map((scope) => (
                  <Badge key={scope} variant="outline" className="text-xs">
                    {scope}
                  </Badge>
                ))}
              </div>
            </div>

            {provider.notes && (
              <div>
                <h4 className="text-sm font-semibold mb-1">Notes</h4>
                <p className="text-sm text-muted-foreground">{provider.notes}</p>
              </div>
            )}

            {provider.connectedServers && provider.connectedServers.length > 0 && (
              <>
                <Separator />
                <div>
                  <h4 className="text-sm font-semibold mb-2 flex items-center gap-1">
                    <Server className="h-3 w-3" />
                    Connected MCP Servers
                  </h4>
                  <div className="space-y-1">
                    {provider.connectedServers.map((server) => (
                      <div key={server.id} className="flex items-center justify-between text-sm">
                        <span className="text-muted-foreground">{server.name}</span>
                        {server.hasOAuthToken && (
                          <Badge variant="outline" className="text-xs">Authenticated</Badge>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}

            {provider.documentationUrl && (
              <div>
                <button
                  onClick={() => window.electronAPI.openExternal(provider.documentationUrl!)}
                  className="inline-flex items-center gap-1 text-sm text-blue-600 dark:text-blue-400 hover:underline"
                >
                  <ExternalLink className="h-3 w-3" />
                  View Documentation
                </button>
              </div>
            )}
          </CardContent>
        </Card>
      ))}

      {providers?.length === 0 && (
        <Card>
          <CardContent className="py-8 text-center text-muted-foreground">No OAuth providers configured</CardContent>
        </Card>
      )}
    </div>
  );
}
