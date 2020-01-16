<?php


namespace OAuth2\library;


use League\OAuth2\Client\OptionProvider\OptionProviderInterface;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Tool\QueryBuilderTrait;
use OAuth2\library\constant\HttpHeader;

class YiChKeJiPostAuthOptionProvider implements OptionProviderInterface
{
    use QueryBuilderTrait;

    /**
     * 请求的认证字段设置
     * @var string
     */
    private $headerAuthorization;

    /**
     * YiChKeJiPostAuthOptionProvider constructor.
     * @param string $clientId
     * @param string $clientSecret
     */
    public function __construct(string $clientId,string $clientSecret)
    {
        $this->headerAuthorization = sprintf("Basic %s",base64_encode($clientId.":".$clientSecret));;
    }

    /**
     * 根据请求方法设置获取请求的参数
     *
     * @param string $method
     * @param array $params
     * @return array
     */
    public function getAccessTokenOptions($method, array $params)
    {
        $options = ['headers' =>
            [
                'content-type' => 'application/x-www-form-urlencoded',
                HttpHeader::ACCEPT => "application/json",
                HttpHeader::AUTHORIZATION => $this->headerAuthorization
            ]
        ];

        if ($method === AbstractProvider::METHOD_POST) {
            $options['body'] = $this->getAccessTokenBody($params);
        }

        return $options;
    }
    /**
     * Returns the request body for requesting an access token.
     *
     * @param  array $params
     * @return string
     */
    protected function getAccessTokenBody(array $params)
    {
        return $this->buildQueryString($params);
    }
}