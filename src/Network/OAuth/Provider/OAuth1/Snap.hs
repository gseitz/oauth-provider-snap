{-# LANGUAGE OverloadedStrings #-}
module Network.OAuth.Provider.OAuth1.Snap where

import           Data.Foldable                          (foldl')
import           Data.Functor                           ((<$>))
import           Data.Map                               (toList)
import           Data.Maybe                             (fromMaybe)
import           Data.Monoid                            ((<>))
import           Network.HTTP.Types
import           Snap.Core                              (MonadSnap, Params,
                                                         Request, Response,
                                                         addHeader,
                                                         emptyResponse,
                                                         getHeader, putResponse,
                                                         rqContextPath,
                                                         rqIsSecure, rqMethod,
                                                         rqPathInfo,
                                                         rqPostParams,
                                                         rqQueryParams,
                                                         rqServerName,
                                                         rqServerPort,
                                                         setResponseStatus)


import qualified Data.ByteString.Char8                  as B
import qualified Data.Text.Encoding                     as E

import           Network.OAuth.Provider.OAuth1.Internal
import           Network.OAuth.Provider.OAuth1.Types


toOAuthRequest :: Request -> OAuthRequest
toOAuthRequest req = OAuthRequest isSecure path query post auth host port method
  where
    auth = fromMaybe [] $ parseAuthentication <$> getHeader "Authentication" req
    host = E.decodeUtf8 $ rqServerName req
    port = rqServerPort req
    isSecure = rqIsSecure req
    method = B.pack . show $ rqMethod req
    path = fmap E.decodeUtf8 $ B.split '/' $ rqContextPath req <> rqPathInfo req
    query = transformParams $ rqQueryParams req
    post = transformParams $ rqPostParams req

toSnapResponse :: MonadSnap m => OAuthResponse -> m Response
toSnapResponse (OAuthResponse status headers content) = do
    putResponse response
    return response
  where
    response = setHeaders $ setResponseStatus (statusCode status) content emptyResponse
    setHeaders resp = foldl' (flip $ uncurry addHeader) resp headers


errorAsSnapResponse :: MonadSnap m => OAuthError -> m Response
errorAsSnapResponse = toSnapResponse . errorAsResponse


transformParams :: Params -> SimpleQueryText
transformParams params = do
    (k, vs) <- toList params
    let kk = E.decodeUtf8 k
    v <- vs
    return (kk, E.decodeUtf8 v)
