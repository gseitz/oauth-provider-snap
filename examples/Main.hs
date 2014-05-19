{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Applicative                 ((<|>))
import           Data.Monoid                         ((<>))
import           Snap.Core                           (Snap, finishWith,
                                                      getsRequest, route,
                                                      writeText)
import           Snap.Http.Server                    (quickHttpServe)

import qualified Data.Text                           as T
import qualified Data.Text.Encoding                  as E

import           Network.OAuth.Provider.OAuth1
import           Network.OAuth.Provider.OAuth1.Snap
import           Network.OAuth.Provider.OAuth1.Types

main :: IO ()
main = snapMain

snapMain :: IO ()
snapMain = quickHttpServe $ snapAuth unprotectedApp protectedApp

snapAuth :: Snap () -> (OAuthParams -> Snap ()) -> Snap ()
snapAuth app protected = do
    oauthReq <- getsRequest toOAuthRequest
    route [
        ("/request", toSnap =<< runOAuth (cfg, oauthReq) twoLeggedRequestTokenRequest),
        ("/access" , toSnap =<< runOAuth (cfg, oauthReq) twoLeggedAccessTokenRequest),
        ("protected", runAuthenticated =<< runOAuth (cfg, oauthReq) authenticated)
        ] <|> app
  where
    toSnap (Left err) = finishWith =<< errorAsSnapResponse err
    toSnap (Right resp) = finishWith =<< toSnapResponse resp

    runAuthenticated (Left err) = toSnap $ Left err
    runAuthenticated (Right params) = protected params

    cfg = twoLeggedConfig consumerLookup accessLookup requestLookup tokenGenerator timestampCheck [Plaintext]

    consumerLookup (ConsumerKey key) = return $ case key of
        "consumer_key" -> Right "consumer_secret"
        k -> Left $ InvalidConsumerKey k

    accessLookup (AccessTokenKey key) = return $ case key of
        "access_key" -> Right "access_secret"
        k -> Left $ InvalidToken k

    requestLookup (RequestTokenKey key) = return $ case key of
        "request_key" -> Right "request_secret"
        k -> Left $ InvalidToken k

    tokenGenerator RequestToken _ = return ("request_key", "request_secret")
    tokenGenerator AccessToken  _ = return ("access_key" , "access_secret")

    timestampCheck _ = return Nothing

unprotectedApp :: Snap ()
unprotectedApp = snapApp "unprotected"

protectedApp :: OAuthParams -> Snap ()
protectedApp params = snapApp $ "protected; accessed by " <> (E.decodeUtf8 . unConsumerKey . opConsumerKey) params

snapApp :: T.Text -> Snap ()
snapApp t = do
    oauthReq <- getsRequest toOAuthRequest
    writeText $ t <> " :: " <> T.intercalate "/" (reqPath oauthReq)

